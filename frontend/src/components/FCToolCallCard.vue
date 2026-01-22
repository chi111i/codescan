<template>
  <div class="fc-tool-call-card" :class="{ 'is-running': isRunning, 'is-success': isSuccess, 'is-failed': isFailed }">
    <!-- Header -->
    <div class="flex items-center justify-between mb-2">
      <div class="flex items-center gap-2">
        <!-- Status Icon -->
        <div class="status-icon" :class="statusClass">
          <svg v-if="isRunning" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
          </svg>
          <svg v-else-if="isSuccess" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
          <svg v-else-if="isFailed" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
          <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
        </div>
        <span class="tool-name">{{ toolCall.tool_name }}</span>
        <span v-if="toolCall.duration_ms" class="text-xs text-gray-400">
          {{ toolCall.duration_ms }}ms
        </span>
      </div>
      <span class="text-xs text-gray-400">{{ formattedTime }}</span>
    </div>

    <!-- Arguments -->
    <div v-if="hasArguments" class="mb-2">
      <button
        @click="showArguments = !showArguments"
        class="text-xs text-blue-500 hover:text-blue-600 flex items-center gap-1"
      >
        <svg class="w-3 h-3 transition-transform" :class="{ 'rotate-90': showArguments }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
        </svg>
        参数
      </button>
      <transition name="expand">
        <div v-if="showArguments" class="mt-2 p-2 bg-gray-50/50 rounded-lg">
          <pre class="text-xs text-gray-600 overflow-x-auto whitespace-pre-wrap">{{ formatJSON(toolCall.arguments) }}</pre>
        </div>
      </transition>
    </div>

    <!-- Result -->
    <div v-if="hasResult" class="mb-2">
      <button
        @click="showResult = !showResult"
        class="text-xs text-green-500 hover:text-green-600 flex items-center gap-1"
      >
        <svg class="w-3 h-3 transition-transform" :class="{ 'rotate-90': showResult }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
        </svg>
        结果
      </button>
      <transition name="expand">
        <div v-if="showResult" class="mt-2 p-2 bg-green-50/50 rounded-lg max-h-40 overflow-y-auto">
          <pre class="text-xs text-gray-600 overflow-x-auto whitespace-pre-wrap">{{ formatResult(toolCall.result) }}</pre>
        </div>
      </transition>
    </div>

    <!-- Error -->
    <div v-if="toolCall.error" class="p-2 bg-red-50/50 rounded-lg">
      <div class="text-xs text-red-600">{{ toolCall.error }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  toolCall: {
    type: Object,
    required: true,
  },
})

const showArguments = ref(false)
const showResult = ref(false)

const isRunning = computed(() => props.toolCall?.status === 'running')
const isSuccess = computed(() => props.toolCall?.status === 'success')
const isFailed = computed(() => props.toolCall?.status === 'failed')

const statusClass = computed(() => {
  if (isRunning.value) return 'bg-blue-100 text-blue-600'
  if (isSuccess.value) return 'bg-green-100 text-green-600'
  if (isFailed.value) return 'bg-red-100 text-red-600'
  return 'bg-gray-100 text-gray-600'
})

const formattedTime = computed(() => {
  const ts = props.toolCall?.timestamp
  if (!ts) return ''
  try {
    const date = new Date(ts)
    return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return ''
  }
})

const hasArguments = computed(() => {
  const args = props.toolCall?.arguments
  return args && typeof args === 'object' && Object.keys(args).length > 0
})

const hasResult = computed(() => {
  return props.toolCall?.result !== null && props.toolCall?.result !== undefined
})

const formatJSON = (obj) => {
  if (!obj) return ''
  try {
    if (typeof obj === 'string') {
      obj = JSON.parse(obj)
    }
    return JSON.stringify(obj, null, 2)
  } catch {
    return String(obj)
  }
}

const formatResult = (result) => {
  if (!result) return ''
  if (typeof result === 'string') {
    // 如果结果是代码，截断显示
    if (result.length > 500) {
      return result.slice(0, 500) + '\n... (已截断)'
    }
    return result
  }
  return formatJSON(result)
}
</script>

<style scoped>
.fc-tool-call-card {
  @apply relative rounded-lg p-3 transition-all duration-200;
  background: rgba(255, 255, 255, 0.6);
  border: 1px solid rgba(200, 200, 200, 0.3);
}

.fc-tool-call-card:hover {
  background: rgba(255, 255, 255, 0.8);
}

.fc-tool-call-card.is-running {
  border-color: rgba(59, 130, 246, 0.4);
  animation: pulse-fc 1.5s ease-in-out infinite;
}

.fc-tool-call-card.is-success {
  border-color: rgba(34, 197, 94, 0.3);
}

.fc-tool-call-card.is-failed {
  border-color: rgba(239, 68, 68, 0.3);
}

@keyframes pulse-fc {
  0%, 100% {
    border-color: rgba(59, 130, 246, 0.3);
  }
  50% {
    border-color: rgba(59, 130, 246, 0.6);
  }
}

.status-icon {
  @apply w-5 h-5 rounded-full flex items-center justify-center;
}

.tool-name {
  @apply font-mono text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700 font-medium;
}

.expand-enter-active,
.expand-leave-active {
  transition: all 0.2s ease;
  overflow: hidden;
}

.expand-enter-from,
.expand-leave-to {
  opacity: 0;
  max-height: 0;
}

.expand-enter-to,
.expand-leave-from {
  opacity: 1;
  max-height: 200px;
}
</style>
