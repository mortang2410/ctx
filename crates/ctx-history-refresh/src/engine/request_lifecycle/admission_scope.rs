use super::*;

/// What ledger admission decided for one refresh request.
///
/// `NoAdmittedRoutes` is the ordinary "nothing to do" case on a fully-indexed
/// install: every requested route is clean, blocked, in flight, or inside a
/// retry backoff. The request must complete without capturing, because those
/// routes carry no admission to acknowledge a result or record a failure.
///
/// It carries the unnarrowed authority so the caller can still fall back to
/// capturing when there is no retained generation to republish: a fresh install
/// has nothing to be a no-op relative to, and capture is what establishes its
/// first generation.
pub(super) enum AdmittedRefreshOutcome {
    Admitted(ctx_history_refresh_execution::AdmittedRefresh),
    NoAdmittedRoutes(ctx_history_refresh_execution::AdmittedRefresh),
}

impl AdmittedRefreshOutcome {
    /// Whether admission found no work, so capture must not run.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_no_work(&self) -> bool {
        matches!(self, Self::NoAdmittedRoutes(_))
    }
}

impl CoreRefreshEngine {
    pub(crate) fn attempt_history_progress(
        &self,
        request_id: &str,
    ) -> Result<ctx_history_capture_model::SharedAttemptHistoryProgress> {
        let state = self.lock_state();
        find_attempt(&state, request_id)
            .and_then(|attempt| attempt.attempt_history_progress.clone())
            .ok_or_else(|| {
                anyhow!("source refresh execution has no active history progress handle")
            })
    }

    pub fn status(&self, request_id: &str) -> Option<RefreshStatus> {
        let state = self.lock_state();
        projected_status_json(&state, request_id).map(RefreshStatus::from_schema_v1_fields)
    }

    pub(super) fn refresh_intent(&self, request_id: &str) -> Option<RefreshIntent> {
        let state = self.lock_state();
        find_attempt(&state, request_id).map(|attempt| attempt.intent.clone())
    }

    #[cfg(test)]
    pub(super) fn refresh_scope(&self, request_id: &str) -> Option<SourceBackedRefreshScope> {
        let state = self.lock_state();
        find_attempt(&state, request_id).map(|attempt| attempt.refresh_scope.clone())
    }

    pub(super) fn reconciliation_demand(
        &self,
        request_id: &str,
    ) -> Option<SourceBackedReconciliationDemand> {
        let state = self.lock_state();
        find_attempt(&state, request_id).map(|attempt| attempt.reconciliation_demand)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn request_catalog_authority_for_test(
        &self,
        request_id: &str,
    ) -> Option<ExplicitSourceCatalogAuthority> {
        let state = self.lock_state();
        find_attempt(&state, request_id)
            .and_then(|attempt| attempt.requested_explicit_source_catalog().cloned())
    }

    pub(super) fn admit_refresh(&self, request_id: &str) -> Result<AdmittedRefreshOutcome> {
        let now_ms = source_route_ledger_now_ms();
        let mut state = self.lock_state();
        if state.route_admissions.contains_key(request_id) {
            bail!("source refresh request `{request_id}` already has retained route admissions");
        }
        let admitted_authority = find_attempt(&state, request_id)
            .and_then(|attempt| attempt.admitted_authority.clone())
            .ok_or_else(|| anyhow!("source refresh execution has no admitted authority"))?;
        let scope = find_attempt(&state, request_id)
            .map(|attempt| attempt.refresh_scope.clone())
            .ok_or_else(|| anyhow!("source refresh request `{request_id}` is unknown"))?;
        let intent = find_attempt(&state, request_id)
            .map(|attempt| attempt.intent.clone())
            .ok_or_else(|| anyhow!("source refresh request `{request_id}` is unknown"))?;
        let authority_matches_scope = match (admitted_authority.coverage(), &scope) {
            (
                ctx_history_refresh_execution::AdmittedRefreshCoverage::CompleteCatalog,
                SourceBackedRefreshScope::All,
            ) => true,
            (
                ctx_history_refresh_execution::AdmittedRefreshCoverage::SelectedRoutes,
                SourceBackedRefreshScope::Exact(routes),
            ) => routes == admitted_authority.exact_routes(),
            _ => false,
        };
        if !authority_matches_scope {
            bail!("source refresh execution does not match its admitted exact scope");
        }
        let exact_routes = admitted_authority.exact_routes().clone();
        if exact_routes.len() > SOURCE_REFRESH_TERMINAL_ROUTE_LIMIT {
            bail!(
                "daemon exact source refresh exceeds {SOURCE_REFRESH_TERMINAL_ROUTE_LIMIT} routes"
            );
        }
        let should_seed = matches!(intent, RefreshIntent::SelectedImport { .. })
            || matches!(scope, SourceBackedRefreshScope::All);
        if matches!(intent, RefreshIntent::SelectedImport { .. }) {
            state
                .automatic_retry_checkpoints
                .retain(|route, _| !exact_routes.contains(route));
            let automatic_retry_checkpoints = state.automatic_retry_checkpoints.clone();
            if let Some(attempt) = find_attempt_mut(&mut state, request_id) {
                attempt.automatic_retry_checkpoints = automatic_retry_checkpoints;
            }
        }
        if should_seed {
            let watermark = state.dirty_routes.seed_watermark();
            for route in &exact_routes {
                state
                    .route_event_watermarks
                    .entry(route.clone())
                    .and_modify(|current| *current = (*current).max(watermark))
                    .or_insert(watermark);
            }
            if intent == RefreshIntent::AutomaticMaintenance
                && find_attempt(&state, request_id)
                    .is_some_and(|attempt| attempt.preserve_route_retry_state)
            {
                // Promotion already checked eligibility. Only clean peers need
                // seeding; reseeding a due retry would erase its failure count.
                state.dirty_routes.seed_clean_exact_routes(
                    exact_routes.iter().cloned(),
                    watermark,
                    now_ms.saturating_sub(1_000),
                );
            } else {
                state.dirty_routes.seed_exact_routes(
                    exact_routes.iter().cloned(),
                    watermark,
                    // Explicit demand bypasses watcher debounce and rearms
                    // selected routes, unlike a scheduled config promotion.
                    now_ms.saturating_sub(1_000),
                );
            }
        }
        // A route that is clean, blocked, in flight, or still inside its retry
        // backoff is simply not due. Admitting the eligible subset keeps those
        // routes dirty for the scheduler instead of failing the whole request:
        // with every route clean, "nothing to do" is a successful no-op.
        let admissions = state.dirty_routes.admit_exact_routes(&exact_routes, now_ms);
        // An exhaustive obligation is transferred to this admitted attempt.
        // Subsequent watcher evidence re-adds its own reason, while failure
        // finalization re-arms this attempt's reason.  Do not leave cleanup
        // to terminal success: it cannot distinguish a pre-admission reason
        // from a newer one recorded while the executor was running.
        if find_attempt(&state, request_id).is_some_and(|attempt| {
            attempt.reconciliation_demand == SourceBackedReconciliationDemand::Exhaustive
        }) {
            for admission in &admissions {
                state
                    .hermes_routes_requiring_exhaustive_recovery
                    .remove(admission.route());
                state
                    .routes_requiring_exhaustive_reconciliation
                    .remove(admission.route());
            }
        }
        state
            .route_admissions
            .insert(request_id.to_owned(), admissions);
        let admitted_watermarks = state
            .route_admissions
            .get(request_id)
            .into_iter()
            .flatten()
            .filter_map(|admission| {
                state
                    .route_event_watermarks
                    .get(admission.route())
                    .copied()
                    .map(|watermark| (admission.route().clone(), watermark))
            })
            .collect::<BTreeMap<_, _>>();
        state
            .route_admission_watermarks
            .insert(request_id.to_owned(), admitted_watermarks);
        // Selected imports inventory every member of their admitted routes.
        // Watcher member hints belong only to automatic maintenance.
        let incremental_exact = find_attempt(&state, request_id).is_some_and(|attempt| {
            intent == RefreshIntent::AutomaticMaintenance
                && attempt.reconciliation_demand == SourceBackedReconciliationDemand::Incremental
                && matches!(scope, SourceBackedRefreshScope::Exact(_))
        });
        let admitted_routes = state
            .route_admissions
            .get(request_id)
            .into_iter()
            .flatten()
            .map(|admission| admission.route().clone())
            .collect::<Vec<_>>();
        let admitted_routes_set = admitted_routes.iter().cloned().collect::<BTreeSet<_>>();
        let mut route_worksets = BTreeMap::new();
        for route in admitted_routes {
            if let Some(workset) = state.route_worksets.remove(&route) {
                if incremental_exact {
                    route_worksets.insert(route, workset);
                }
            }
        }
        // An automatic route split can only be planned against a full-catalog
        // publication with exhaustive demand: `prepare_automatic_route_splits`
        // rejects an Exact scope. Narrowing an All attempt to Exact would turn
        // a split migration into a failed refresh, so leave those unnarrowed.
        let requires_full_catalog_publication =
            find_attempt(&state, request_id).is_some_and(|attempt| {
                matches!(scope, SourceBackedRefreshScope::All)
                    && attempt.reconciliation_demand == SourceBackedReconciliationDemand::Exhaustive
            });
        // Nothing was admissible: every requested route is clean, blocked,
        // in flight, or inside a retry backoff. For AUTOMATIC MAINTENANCE that
        // is ordinary housekeeping with no work to do. It must not capture:
        // scanning routes the ledger does not own means a failure could reach
        // neither acknowledgement nor backoff, which is how "nothing to do"
        // became a failed refresh.
        //
        // An EXPLICIT demand is different. `SelectedImport` is a user or CLI
        // request to (re-)index those routes now, and it seeds them dirty
        // above precisely so admission cannot come back empty. If it somehow
        // does, fall through to capture: honouring the explicit request is
        // correct, and an unexpected empty admission must not silently become
        // a no-op that reports success.
        let automatic_no_work =
            admitted_routes_set.is_empty() && intent == RefreshIntent::AutomaticMaintenance;
        if automatic_no_work {
            return Ok(AdmittedRefreshOutcome::NoAdmittedRoutes(
                admitted_authority.with_execution_facts(route_worksets)?,
            ));
        }
        let admitted_authority = if requires_full_catalog_publication {
            admitted_authority
        } else {
            // Physical execution must cover exactly the admitted subset, or a
            // deferred route gets scanned with no admission to acknowledge it
            // and its failure escapes ledger backoff.
            admitted_authority.narrow_to_admitted(&admitted_routes_set)?
        };
        Ok(AdmittedRefreshOutcome::Admitted(
            admitted_authority.with_execution_facts(route_worksets)?,
        ))
    }

    #[cfg(test)]
    pub fn admit_refresh_scope_for_test(
        &self,
        request_id: &str,
        scope: &SourceBackedRefreshScope,
    ) -> Result<BTreeSet<SourceRouteIdentity>> {
        if self.refresh_scope(request_id).as_ref() != Some(scope) {
            bail!("test source refresh scope does not match the queued request");
        }
        self.admit_refresh(request_id).map(|outcome| match outcome {
            AdmittedRefreshOutcome::Admitted(_) | AdmittedRefreshOutcome::NoAdmittedRoutes(_) => {
                BTreeSet::new()
            }
        })
    }

    /// Whether real admission found work for this request.
    ///
    /// Returns false when admission had nothing due, which is the successful
    /// no-op that must not reach capture.
    #[cfg(test)]
    pub fn admission_found_work_for_test(&self, request_id: &str) -> Result<bool> {
        Ok(!self.admit_refresh(request_id)?.is_no_work())
    }

    /// Whether ledger admission found any route due for this request.
    #[cfg(test)]
    pub fn admitted_routes_for_test(
        &self,
        request_id: &str,
    ) -> Result<BTreeSet<SourceRouteIdentity>> {
        let state = self.lock_state();
        Ok(state
            .route_admissions
            .get(request_id)
            .into_iter()
            .flatten()
            .map(|admission| admission.route().clone())
            .collect())
    }
}
