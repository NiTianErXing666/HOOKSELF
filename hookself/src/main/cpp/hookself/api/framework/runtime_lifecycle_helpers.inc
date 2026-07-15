class RuntimeLease {
  public:
    RuntimeLease() = default;

    ~RuntimeLease() {
        Release();
    }

    RuntimeLease(const RuntimeLease&) = delete;
    RuntimeLease& operator=(const RuntimeLease&) = delete;

    int32_t AcquireLocked(HookselfFramework* framework) {
        if (framework == nullptr || framework->runtime == nullptr) {
            return HOOKSELF_E_INVALID_STATE;
        }
        if (framework->runtime_users == UINT32_MAX) {
            return HOOKSELF_E_CAPACITY;
        }
        framework_ = framework;
        runtime_ = framework->runtime;
        generation_ = framework->runtime_generation;
        ++framework->runtime_users;
        active_ = true;
        return HOOKSELF_OK;
    }

    void ReleaseLocked() {
        if (!active_) {
            return;
        }
        if (framework_->runtime_users != 0U) {
            --framework_->runtime_users;
        }
        if (framework_->runtime_users == 0U) {
            pthread_cond_broadcast(&framework_->lifecycle_cv);
        }
        active_ = false;
    }

    void Release() {
        if (!active_) {
            return;
        }
        if (pthread_mutex_lock(&framework_->mutex) != 0) {
            return;
        }
        ReleaseLocked();
        pthread_mutex_unlock(&framework_->mutex);
    }

    HookselfRuntime* runtime() const { return runtime_; }
    uint64_t generation() const { return generation_; }

  private:
    HookselfFramework* framework_ = nullptr;
    HookselfRuntime* runtime_ = nullptr;
    uint64_t generation_ = 0U;
    bool active_ = false;
};

int32_t RuntimeForForwarding(HookselfFramework* framework,
                             RuntimeLease* lease) {
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    int32_t result = HOOKSELF_OK;
    if (framework->lifecycle_busy != 0U) {
        result = HOOKSELF_E_BUSY;
    } else if (framework->runtime == nullptr) {
        result = HOOKSELF_E_INVALID_STATE;
    } else {
        result = lease->AcquireLocked(framework);
    }
    pthread_mutex_unlock(&framework->mutex);
    return result;
}

void FinishLifecycle(HookselfFramework* framework) {
    if (pthread_mutex_lock(&framework->mutex) == 0) {
        framework->runtime_starting = 0U;
        framework->lifecycle_busy = 0U;
        pthread_cond_broadcast(&framework->lifecycle_cv);
        pthread_mutex_unlock(&framework->mutex);
    }
}
