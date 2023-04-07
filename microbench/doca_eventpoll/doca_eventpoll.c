int doca_epoll_wait(struct doca_workq * workq, struct doca_event * events, int maxevents) {
    int nevents = 0;
	doca_error_t result;
    while (nevents < maxevents) {
        /* Try to retrieve some event */
        result = doca_workq_progress_retrieve(workq, &events[nevents], DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
        if (result == DOCA_SUCCESS) {
            nevents++;
        } else if (result == DOCA_ERROR_AGAIN) {
            break;
        } else {
            DOCA_LOG_ERR("Failed to dequeue RegEx job response");
        }
    }

    return nevents;
}