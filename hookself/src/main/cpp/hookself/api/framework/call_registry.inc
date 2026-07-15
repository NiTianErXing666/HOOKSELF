void FinalizeFramework(HookselfFramework* framework) {
    if (framework == nullptr) {
        return;
    }
    HookselfRuntime* const runtime = framework->runtime;
    framework->runtime = nullptr;
    if (runtime != nullptr) {
        hookself_destroy(runtime);
    }
    for (uint32_t index = 0;
         index < framework->config.virtual_file_count; ++index) {
        delete[] framework->virtual_contents[index];
        framework->virtual_contents[index] = nullptr;
    }
    pthread_cond_destroy(&framework->lifecycle_cv);
    pthread_mutex_destroy(&framework->mutex);
    delete framework;
}

bool ThreadHasFrameworkCall(const HookselfFramework* framework) {
    for (FrameworkCallFrame* frame = gFrameworkCallFrame;
         frame != nullptr; frame = frame->previous) {
        if (frame->framework == framework) {
            return true;
        }
    }
    return false;
}

bool RegisterFramework(HookselfFramework* framework) {
    if (framework == nullptr ||
        pthread_mutex_lock(&gFrameworkRegistryMutex) != 0) {
        return false;
    }
    framework->registry_next = gFrameworkRegistryHead;
    gFrameworkRegistryHead = framework;
    pthread_mutex_unlock(&gFrameworkRegistryMutex);
    return true;
}

int32_t BeginFrameworkCall(HookselfFramework* framework) {
    if (framework == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    const bool nested = ThreadHasFrameworkCall(framework);
    if (pthread_mutex_lock(&gFrameworkRegistryMutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    bool registered = false;
    for (const HookselfFramework* candidate = gFrameworkRegistryHead;
         candidate != nullptr; candidate = candidate->registry_next) {
        if (candidate == framework) {
            registered = true;
            break;
        }
    }
    if (!registered && !nested) {
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        return HOOKSELF_E_INTERNAL;
    }
    if (framework->closing != 0U && !nested) {
        pthread_mutex_unlock(&framework->mutex);
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    if (framework->active_calls == UINT32_MAX) {
        pthread_mutex_unlock(&framework->mutex);
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        return HOOKSELF_E_CAPACITY;
    }
    ++framework->active_calls;
    pthread_mutex_unlock(&framework->mutex);
    pthread_mutex_unlock(&gFrameworkRegistryMutex);
    return HOOKSELF_OK;
}

bool EndFrameworkCall(HookselfFramework* framework) {
    bool finalize = false;
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return false;
    }
    if (framework->active_calls != 0U) {
        --framework->active_calls;
    }
    if (framework->closing != 0U && framework->active_calls == 0U) {
        pthread_cond_broadcast(&framework->lifecycle_cv);
        if (framework->deferred_destroy != 0U &&
            framework->destroy_waiter == 0U) {
            framework->deferred_destroy = 0U;
            finalize = true;
        }
    }
    pthread_mutex_unlock(&framework->mutex);
    return finalize;
}

class FrameworkCall {
  public:
    explicit FrameworkCall(HookselfFramework* framework)
        : frame_{framework, gFrameworkCallFrame} {
        result_ = BeginFrameworkCall(framework);
        if (result_ == HOOKSELF_OK) {
            gFrameworkCallFrame = &frame_;
            active_ = true;
        }
    }

    ~FrameworkCall() {
        if (!active_) {
            return;
        }
        gFrameworkCallFrame = frame_.previous;
        if (EndFrameworkCall(frame_.framework)) {
            FinalizeFramework(frame_.framework);
        }
    }

    FrameworkCall(const FrameworkCall&) = delete;
    FrameworkCall& operator=(const FrameworkCall&) = delete;

    int32_t result() const { return result_; }

  private:
    FrameworkCallFrame frame_{};
    int32_t result_ = HOOKSELF_E_INVALID_ARGUMENT;
    bool active_ = false;
};

