<template>
  <div v-if="progress" class="analysis-progress-bar">
    <!-- Header -->
    <div class="flex items-center justify-between mb-2">
      <div class="flex items-center gap-2">
        <div class="thinking-indicator">
          <div class="dot"></div>
          <div class="dot"></div>
          <div class="dot"></div>
        </div>
        <span class="text-sm font-medium text-gray-700">正在分析漏洞触发点</span>
      </div>
      <span class="text-sm font-medium text-blue-600">{{ progress.current }}/{{ progress.total }}</span>
    </div>

    <!-- Progress Bar -->
    <div class="progress-track">
      <div
        class="progress-fill"
        :style="{ width: `${progress.percentage}%` }"
      >
        <div class="progress-shine"></div>
      </div>
    </div>

    <!-- Current Site Info -->
    <div v-if="progress.current_site" class="mt-2 text-xs text-gray-500 flex items-center gap-1">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
      </svg>
      <span class="truncate">{{ formatSiteInfo(progress.current_site) }}</span>
    </div>

    <!-- Percentage Text -->
    <div class="mt-1 text-xs text-gray-400 text-right">
      已完成 {{ progress.percentage }}%
    </div>
  </div>
</template>

<script setup>
defineProps({
  progress: {
    type: Object,
    default: null,
  },
})

const formatSiteInfo = (site) => {
  if (!site) return ''
  if (typeof site === 'string') return site
  if (site.file_path && site.line) {
    return `${site.file_path}:${site.line}`
  }
  if (site.sink_name) {
    return `检查 ${site.sink_name}`
  }
  return JSON.stringify(site).slice(0, 50)
}
</script>

<style scoped>
.analysis-progress-bar {
  @apply relative rounded-xl p-4;
  background: rgba(255, 255, 255, 0.8);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(59, 130, 246, 0.2);
  box-shadow: 0 2px 12px rgba(59, 130, 246, 0.08);
}

.thinking-indicator {
  @apply flex items-center gap-1;
}

.thinking-indicator .dot {
  @apply w-1.5 h-1.5 rounded-full bg-blue-500;
  animation: bounce-dot 1.4s ease-in-out infinite;
}

.thinking-indicator .dot:nth-child(1) {
  animation-delay: 0s;
}

.thinking-indicator .dot:nth-child(2) {
  animation-delay: 0.2s;
}

.thinking-indicator .dot:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes bounce-dot {
  0%, 80%, 100% {
    transform: scale(0.8);
    opacity: 0.5;
  }
  40% {
    transform: scale(1.2);
    opacity: 1;
  }
}

.progress-track {
  @apply h-2 rounded-full overflow-hidden;
  background: rgba(59, 130, 246, 0.15);
}

.progress-fill {
  @apply h-full rounded-full relative overflow-hidden transition-all duration-500 ease-out;
  background: linear-gradient(90deg, #3b82f6, #60a5fa);
}

.progress-shine {
  @apply absolute inset-0;
  background: linear-gradient(
    90deg,
    transparent 0%,
    rgba(255, 255, 255, 0.4) 50%,
    transparent 100%
  );
  animation: shimmer 2s ease-in-out infinite;
}

@keyframes shimmer {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(100%);
  }
}
</style>
