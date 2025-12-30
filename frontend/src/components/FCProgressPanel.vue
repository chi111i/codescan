<template>
  <div class="fc-progress-panel glass-card rounded-xl p-4">
    <!-- Header -->
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center">
          <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
        </div>
        <div>
          <h3 class="text-sm font-semibold text-gray-800">Function Calling 分析</h3>
          <p class="text-xs text-gray-500">
            LLM 主动调用工具进行代码探索
          </p>
        </div>
      </div>

      <!-- Status Badge -->
      <div class="status-badge" :class="statusClass">
        <svg v-if="isAnalyzing" class="w-3 h-3 animate-spin mr-1" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
        </svg>
        {{ statusText }}
      </div>
    </div>

    <!-- Current Sink -->
    <div v-if="currentSink" class="mb-4 p-3 bg-amber-50/50 rounded-lg border border-amber-200/50">
      <div class="text-xs text-amber-600 mb-1">当前分析触发点</div>
      <div class="font-mono text-sm text-amber-800">{{ currentSink }}</div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-3 gap-3 mb-4">
      <div class="stat-card">
        <div class="stat-value">{{ currentTurn }}</div>
        <div class="stat-label">对话轮次</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ totalToolCalls }}</div>
        <div class="stat-label">工具调用</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ findingsCount }}</div>
        <div class="stat-label">发现问题</div>
      </div>
    </div>

    <!-- Tool Calls List -->
    <div v-if="toolCalls.length > 0" class="space-y-2">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs text-gray-500 font-medium">最近工具调用</span>
        <button
          v-if="toolCalls.length > 5"
          @click="showAll = !showAll"
          class="text-xs text-blue-500 hover:text-blue-600"
        >
          {{ showAll ? '收起' : `显示全部 (${toolCalls.length})` }}
        </button>
      </div>
      <div class="space-y-2 max-h-[300px] overflow-y-auto">
        <FCToolCallCard
          v-for="tc in displayedToolCalls"
          :key="tc.id"
          :tool-call="tc"
        />
      </div>
    </div>

    <!-- Empty State -->
    <div v-else class="text-center py-6 text-gray-400">
      <svg class="w-10 h-10 mx-auto mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>
      </svg>
      <p class="text-sm">等待工具调用...</p>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import FCToolCallCard from './FCToolCallCard.vue'

const props = defineProps({
  currentSink: {
    type: String,
    default: '',
  },
  currentTurn: {
    type: Number,
    default: 0,
  },
  totalToolCalls: {
    type: Number,
    default: 0,
  },
  toolCalls: {
    type: Array,
    default: () => [],
  },
  findingsCount: {
    type: Number,
    default: 0,
  },
  status: {
    type: String,
    default: 'idle', // idle, analyzing, completed, failed
  },
})

const showAll = ref(false)

const isAnalyzing = computed(() => props.status === 'analyzing')

const statusClass = computed(() => {
  switch (props.status) {
    case 'analyzing':
      return 'bg-blue-100 text-blue-700'
    case 'completed':
      return 'bg-green-100 text-green-700'
    case 'failed':
      return 'bg-red-100 text-red-700'
    default:
      return 'bg-gray-100 text-gray-600'
  }
})

const statusText = computed(() => {
  switch (props.status) {
    case 'analyzing':
      return '分析中'
    case 'completed':
      return '已完成'
    case 'failed':
      return '失败'
    default:
      return '等待中'
  }
})

const displayedToolCalls = computed(() => {
  if (showAll.value) {
    return [...props.toolCalls].reverse()
  }
  return [...props.toolCalls].reverse().slice(0, 5)
})
</script>

<style scoped>
.fc-progress-panel {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
}

.status-badge {
  @apply flex items-center px-2.5 py-1 text-xs font-medium rounded-full;
}

.stat-card {
  @apply p-3 rounded-lg text-center;
  background: rgba(243, 244, 246, 0.5);
}

.stat-value {
  @apply text-xl font-bold text-gray-800;
}

.stat-label {
  @apply text-xs text-gray-500 mt-0.5;
}
</style>
