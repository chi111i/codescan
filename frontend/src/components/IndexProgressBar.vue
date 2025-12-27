<template>
  <div v-if="visible" class="index-progress-bar">
    <!-- Header -->
    <div class="flex items-center justify-between mb-3">
      <div class="flex items-center gap-2">
        <div v-if="isActive" class="indexing-indicator">
          <div class="pulse-ring"></div>
          <div class="pulse-core"></div>
        </div>
        <svg v-else class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
        </svg>
        <span class="text-sm font-medium text-gray-700">{{ statusText }}</span>
      </div>
      <div class="flex items-center gap-3">
        <span v-if="progress.total_units > 0" class="text-xs text-gray-500">
          {{ progress.processed_units }}/{{ progress.total_units }} 代码单元
        </span>
        <span class="text-sm font-semibold text-indigo-600">{{ percentage }}%</span>
      </div>
    </div>

    <!-- Progress Bar -->
    <div class="progress-track">
      <div
        class="progress-fill"
        :class="{ 'completed': progress.status === 'completed' }"
        :style="{ width: `${percentage}%` }"
      >
        <div v-if="isActive" class="progress-shine"></div>
      </div>
    </div>

    <!-- Details Row -->
    <div class="mt-2 flex items-center justify-between text-xs text-gray-500">
      <div class="flex items-center gap-1">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
        </svg>
        <span class="truncate max-w-xs">{{ progress.current_step || '准备中...' }}</span>
      </div>
      <div v-if="progress.total_files > 0" class="flex items-center gap-1">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
        </svg>
        <span>{{ progress.processed_files }}/{{ progress.total_files }} 文件</span>
      </div>
    </div>

    <!-- Embedding Progress (sub-progress) -->
    <div v-if="showEmbeddingProgress" class="mt-3 pt-3 border-t border-gray-100">
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs text-gray-500">向量化进度</span>
        <span class="text-xs font-medium text-blue-600">{{ embeddingPercentage }}%</span>
      </div>
      <div class="progress-track-sm">
        <div
          class="progress-fill-sm"
          :style="{ width: `${embeddingPercentage}%` }"
        ></div>
      </div>
    </div>

    <!-- Error Message -->
    <div v-if="progress.error_message" class="mt-3 p-2 bg-red-50 rounded-lg text-xs text-red-600">
      <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      {{ progress.error_message }}
    </div>

    <!-- Close button for completed state -->
    <button v-if="!isActive" @click="$emit('close')" class="absolute top-2 right-2 text-gray-400 hover:text-gray-600">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
      </svg>
    </button>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  progress: {
    type: Object,
    required: true,
    default: () => ({
      status: 'pending',
      progress: 0,
      current_step: '',
      total_files: 0,
      processed_files: 0,
      total_units: 0,
      processed_units: 0,
      embedding_progress: 0,
      error_message: null,
    }),
  },
  visible: {
    type: Boolean,
    default: true,
  },
})

defineEmits(['close'])

const isActive = computed(() => {
  return ['pending', 'scanning', 'parsing', 'embedding', 'storing'].includes(props.progress.status)
})

const percentage = computed(() => {
  return Math.round((props.progress.progress || 0) * 100)
})

const embeddingPercentage = computed(() => {
  return Math.round((props.progress.embedding_progress || 0) * 100)
})

const showEmbeddingProgress = computed(() => {
  return props.progress.status === 'embedding' && props.progress.embedding_progress > 0
})

const statusText = computed(() => {
  const statusMap = {
    pending: '等待开始...',
    scanning: '扫描文件中...',
    parsing: '解析代码中...',
    embedding: '生成向量中...',
    storing: '存储索引中...',
    completed: '索引完成',
    failed: '索引失败',
  }
  return statusMap[props.progress.status] || '未知状态'
})
</script>

<style scoped>
.index-progress-bar {
  @apply relative rounded-xl p-4;
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(99, 102, 241, 0.2);
  box-shadow: 0 4px 20px rgba(99, 102, 241, 0.1);
}

.indexing-indicator {
  @apply relative w-5 h-5;
}

.pulse-ring {
  @apply absolute inset-0 rounded-full;
  background: rgba(99, 102, 241, 0.3);
  animation: pulse-ring 1.5s ease-out infinite;
}

.pulse-core {
  @apply absolute inset-1 rounded-full bg-indigo-500;
}

@keyframes pulse-ring {
  0% {
    transform: scale(0.8);
    opacity: 1;
  }
  100% {
    transform: scale(1.5);
    opacity: 0;
  }
}

.progress-track {
  @apply h-2.5 rounded-full overflow-hidden;
  background: rgba(99, 102, 241, 0.1);
}

.progress-fill {
  @apply h-full rounded-full relative overflow-hidden transition-all duration-300 ease-out;
  background: linear-gradient(90deg, #6366f1, #8b5cf6);
}

.progress-fill.completed {
  background: linear-gradient(90deg, #10b981, #34d399);
}

.progress-shine {
  @apply absolute inset-0;
  background: linear-gradient(
    90deg,
    transparent 0%,
    rgba(255, 255, 255, 0.4) 50%,
    transparent 100%
  );
  animation: shimmer 1.5s ease-in-out infinite;
}

@keyframes shimmer {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(100%);
  }
}

.progress-track-sm {
  @apply h-1.5 rounded-full overflow-hidden;
  background: rgba(59, 130, 246, 0.1);
}

.progress-fill-sm {
  @apply h-full rounded-full transition-all duration-300 ease-out;
  background: linear-gradient(90deg, #3b82f6, #60a5fa);
}
</style>
