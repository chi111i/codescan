<template>
  <div class="llm-call-card" :class="{ 'is-thinking': isThinking, 'is-new': isNew }">
    <!-- Header -->
    <div class="flex items-center justify-between mb-3">
      <div class="flex items-center gap-2">
        <!-- Status Icon -->
        <div class="status-icon" :class="statusClass">
          <svg v-if="isThinking" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
          </svg>
          <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <span class="text-sm font-medium" :class="isThinking ? 'text-blue-600' : 'text-gray-700'">
          {{ isThinking ? 'LLM 思考中...' : 'LLM 响应' }}
        </span>
      </div>
      <span class="text-xs text-gray-400">{{ formattedTime }}</span>
    </div>

    <!-- Question Preview -->
    <div v-if="call.current_question" class="mb-3">
      <div class="text-xs text-gray-500 mb-1">当前问题</div>
      <div class="text-sm text-gray-600 bg-gray-50/50 rounded-lg px-3 py-2 line-clamp-2">
        {{ call.current_question }}
      </div>
    </div>

    <!-- Content Preview (only when completed) -->
    <div v-if="!isThinking && (summaryContent || fullContent)" class="mb-3">
      <div class="text-xs text-gray-500 mb-1 flex items-center justify-between">
        <span>响应摘要</span>
        <button
          v-if="canExpandContent"
          @click="showFullContent = !showFullContent"
          class="text-blue-500 hover:text-blue-600 transition-colors"
        >
          {{ showFullContent ? '收起' : '展开完整' }}
        </button>
      </div>
      <div class="text-sm text-gray-700 bg-blue-50/30 rounded-lg px-3 py-2">
        <template v-if="showFullContent">
          <div class="whitespace-pre-wrap max-h-72 overflow-y-auto dark-scroll">{{ fullContent }}</div>
        </template>
        <template v-else>
          <div class="line-clamp-3">{{ summaryContent }}</div>
        </template>
      </div>
    </div>

    <!-- Tool Calls -->
    <div v-if="call.tool_calls && call.tool_calls.length > 0" class="mb-3">
      <div class="text-xs text-gray-500 mb-2 flex items-center gap-1">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
        </svg>
        <span>工具调用 ({{ call.tool_calls.length }})</span>
      </div>
      <div class="space-y-2">
        <div
          v-for="(tc, idx) in displayedToolCalls"
          :key="tc.id || idx"
          class="tool-call-item"
        >
          <div class="flex items-center gap-2">
            <span class="tool-name">{{ tc.name }}</span>
            <span v-if="tc.arguments" class="text-xs text-gray-400 truncate max-w-[200px]">
              {{ formatArguments(tc.arguments) }}
            </span>
          </div>
        </div>
        <button
          v-if="call.tool_calls.length > 3"
          @click="showAllToolCalls = !showAllToolCalls"
          class="text-xs text-blue-500 hover:text-blue-600"
        >
          {{ showAllToolCalls ? '收起' : `显示全部 ${call.tool_calls.length} 个工具调用` }}
        </button>
      </div>
    </div>

    <!-- Stats -->
    <div v-if="!isThinking && call.usage" class="flex items-center gap-4 text-xs text-gray-400 pt-2 border-t border-gray-100">
      <span class="flex items-center gap-1">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"/>
        </svg>
        {{ call.usage.total_tokens || 0 }} tokens
      </span>
      <span v-if="call.messages_count" class="flex items-center gap-1">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
        </svg>
        {{ call.messages_count }} 消息
      </span>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  call: {
    type: Object,
    required: true,
  },
  isNew: {
    type: Boolean,
    default: false,
  },
})

const showFullContent = ref(false)
const showAllToolCalls = ref(false)

const isThinking = computed(() => props.call.status === 'thinking')

const statusClass = computed(() => {
  return isThinking.value
    ? 'bg-blue-100 text-blue-600'
    : 'bg-green-100 text-green-600'
})

const formattedTime = computed(() => {
  const ts = props.call.started_at || props.call.finished_at
  if (!ts) return ''
  const date = new Date(ts)
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
})

const displayedToolCalls = computed(() => {
  if (!props.call.tool_calls) return []
  return showAllToolCalls.value
    ? props.call.tool_calls
    : props.call.tool_calls.slice(0, 3)
})

const fullContent = computed(() => {
  return props.call.content || props.call.content_preview || ''
})

const summaryContent = computed(() => {
  if (props.call.content_preview) {
    return props.call.content_preview
  }
  const content = fullContent.value || ''
  const PREVIEW_LIMIT = 320
  return content.length > PREVIEW_LIMIT
    ? `${content.slice(0, PREVIEW_LIMIT)}...`
    : content
})

const canExpandContent = computed(() => {
  if (!fullContent.value) return false
  return summaryContent.value !== fullContent.value
})

const formatArguments = (args) => {
  if (!args) return ''
  if (typeof args === 'string') {
    try {
      args = JSON.parse(args)
    } catch {
      return args.slice(0, 50)
    }
  }
  const str = JSON.stringify(args)
  return str.length > 50 ? str.slice(0, 50) + '...' : str
}
</script>

<style scoped>
.llm-call-card {
  @apply relative rounded-xl p-4 transition-all duration-300;
  background: rgba(255, 255, 255, 0.75);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.5);
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.04);
}

.llm-call-card:hover {
  background: rgba(255, 255, 255, 0.85);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
}

.llm-call-card.is-thinking {
  border-color: rgba(59, 130, 246, 0.3);
  animation: pulse-border 2s ease-in-out infinite;
}

.llm-call-card.is-new {
  animation: highlight-new 0.5s ease-out;
}

@keyframes pulse-border {
  0%, 100% {
    border-color: rgba(59, 130, 246, 0.3);
    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.1);
  }
  50% {
    border-color: rgba(59, 130, 246, 0.5);
    box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.05);
  }
}

@keyframes highlight-new {
  0% {
    background: rgba(59, 130, 246, 0.15);
    transform: translateX(-4px);
  }
  100% {
    background: rgba(255, 255, 255, 0.75);
    transform: translateX(0);
  }
}

.status-icon {
  @apply w-6 h-6 rounded-full flex items-center justify-center;
}

.tool-call-item {
  @apply bg-gray-50/50 rounded-lg px-3 py-2 text-sm;
}

.tool-name {
  @apply font-mono text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700;
}

.line-clamp-2 {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.line-clamp-3 {
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
</style>
