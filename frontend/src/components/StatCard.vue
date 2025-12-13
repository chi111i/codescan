<template>
  <div class="stat-card-enhanced group" :class="sizeClass">
    <!-- 背景装饰 -->
    <div class="absolute inset-0 overflow-hidden rounded-2xl">
      <div
        class="absolute -top-12 -right-12 w-32 h-32 rounded-full opacity-20 blur-2xl transition-all duration-500 group-hover:scale-150"
        :class="glowColorClass"
      ></div>
    </div>

    <div class="relative flex items-center gap-5">
      <!-- 图标容器 -->
      <div
        class="icon-container flex-shrink-0"
        :class="[iconSizeClass, gradientClass]"
      >
        <component :is="iconComponent" class="icon-inner" :class="iconInnerSizeClass" />
        <!-- 脉冲效果 -->
        <div v-if="pulse" class="pulse-ring" :class="pulseColorClass"></div>
      </div>

      <!-- 内容区域 -->
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-gray-500 mb-1">{{ title }}</div>
        <div class="flex items-baseline gap-2">
          <span class="text-3xl font-bold text-gray-800 tabular-nums">
            {{ animatedValue }}
          </span>
          <span v-if="unit" class="text-sm text-gray-500">{{ unit }}</span>
        </div>

        <!-- 趋势指示器 -->
        <div v-if="trend !== undefined" class="flex items-center gap-1 mt-2">
          <span
            class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
            :class="trendClass"
          >
            <svg
              v-if="trend > 0"
              class="w-3 h-3 mr-0.5"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path fill-rule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd"/>
            </svg>
            <svg
              v-else-if="trend < 0"
              class="w-3 h-3 mr-0.5"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path fill-rule="evenodd" d="M14.707 10.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V5a1 1 0 012 0v7.586l2.293-2.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
            </svg>
            <span v-else class="w-3 h-3 mr-0.5 inline-flex items-center justify-center">-</span>
            {{ Math.abs(trend) }}%
          </span>
          <span class="text-xs text-gray-400">{{ trendLabel }}</span>
        </div>

        <!-- 迷你进度条 -->
        <div v-if="progress !== undefined" class="mt-3">
          <div class="flex justify-between text-xs text-gray-500 mb-1">
            <span>{{ progressLabel }}</span>
            <span>{{ progress }}%</span>
          </div>
          <div class="h-1.5 bg-gray-200/50 rounded-full overflow-hidden">
            <div
              class="h-full rounded-full transition-all duration-700"
              :class="progressColorClass"
              :style="{ width: `${progress}%` }"
            ></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch, onMounted, h } from 'vue'

const props = defineProps({
  title: String,
  value: [Number, String],
  icon: String,
  color: {
    type: String,
    default: 'blue',
  },
  unit: String,
  trend: Number,
  trendLabel: {
    type: String,
    default: '较上周',
  },
  progress: Number,
  progressLabel: {
    type: String,
    default: '完成度',
  },
  pulse: Boolean,
  size: {
    type: String,
    default: 'normal',
  },
})

// 动画数值
const animatedValue = ref(0)

const animateValue = (target) => {
  const start = animatedValue.value
  const end = typeof target === 'number' ? target : parseInt(target) || 0
  const duration = 800
  const startTime = performance.now()

  const animate = (currentTime) => {
    const elapsed = currentTime - startTime
    const progress = Math.min(elapsed / duration, 1)
    const easeOutQuart = 1 - Math.pow(1 - progress, 4)
    animatedValue.value = Math.round(start + (end - start) * easeOutQuart)

    if (progress < 1) {
      requestAnimationFrame(animate)
    }
  }

  requestAnimationFrame(animate)
}

watch(() => props.value, (newVal) => {
  if (typeof newVal === 'number') {
    animateValue(newVal)
  } else {
    animatedValue.value = newVal
  }
}, { immediate: true })

onMounted(() => {
  if (typeof props.value === 'number') {
    animateValue(props.value)
  } else {
    animatedValue.value = props.value
  }
})

const sizeClass = computed(() => {
  return props.size === 'large' ? 'p-8' : 'p-6'
})

const iconSizeClass = computed(() => {
  return props.size === 'large' ? 'w-16 h-16' : 'w-14 h-14'
})

const iconInnerSizeClass = computed(() => {
  return props.size === 'large' ? 'w-8 h-8' : 'w-7 h-7'
})

const gradientClass = computed(() => {
  const gradients = {
    blue: 'bg-gradient-to-br from-blue-500 to-blue-600',
    purple: 'bg-gradient-to-br from-purple-500 to-pink-600',
    green: 'bg-gradient-to-br from-green-500 to-emerald-600',
    orange: 'bg-gradient-to-br from-orange-500 to-red-500',
    red: 'bg-gradient-to-br from-red-500 to-rose-600',
    cyan: 'bg-gradient-to-br from-cyan-500 to-blue-500',
    indigo: 'bg-gradient-to-br from-indigo-500 to-purple-600',
  }
  return gradients[props.color] || gradients.blue
})

const glowColorClass = computed(() => {
  const colors = {
    blue: 'bg-blue-400',
    purple: 'bg-purple-400',
    green: 'bg-green-400',
    orange: 'bg-orange-400',
    red: 'bg-red-400',
    cyan: 'bg-cyan-400',
    indigo: 'bg-indigo-400',
  }
  return colors[props.color] || colors.blue
})

const pulseColorClass = computed(() => {
  const colors = {
    blue: 'bg-blue-400',
    purple: 'bg-purple-400',
    green: 'bg-green-400',
    orange: 'bg-orange-400',
    red: 'bg-red-400',
  }
  return colors[props.color] || colors.blue
})

const progressColorClass = computed(() => {
  const colors = {
    blue: 'bg-gradient-to-r from-blue-500 to-blue-400',
    purple: 'bg-gradient-to-r from-purple-500 to-pink-400',
    green: 'bg-gradient-to-r from-green-500 to-emerald-400',
    orange: 'bg-gradient-to-r from-orange-500 to-yellow-400',
    red: 'bg-gradient-to-r from-red-500 to-rose-400',
  }
  return colors[props.color] || colors.blue
})

const trendClass = computed(() => {
  if (props.trend > 0) {
    return 'bg-green-100 text-green-700'
  } else if (props.trend < 0) {
    return 'bg-red-100 text-red-700'
  }
  return 'bg-gray-100 text-gray-600'
})

// 图标组件
const CodeIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4' })
  ])
}

const ScanIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' })
  ])
}

const WarningIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' })
  ])
}

const ShieldIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' })
  ])
}

const ChartIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' })
  ])
}

const BugIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 19l9 2-9-18-9 18 9-2zm0 0v-8' })
  ])
}

const iconComponent = computed(() => {
  const icons = {
    code: CodeIcon,
    scan: ScanIcon,
    warning: WarningIcon,
    shield: ShieldIcon,
    chart: ChartIcon,
    bug: BugIcon,
  }
  return icons[props.icon] || CodeIcon
})
</script>

<style scoped>
.stat-card-enhanced {
  @apply relative rounded-2xl overflow-hidden;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(30px) saturate(180%);
  -webkit-backdrop-filter: blur(30px) saturate(180%);
  border: 1px solid rgba(255, 255, 255, 0.6);
  box-shadow:
    0 4px 24px rgba(0, 0, 0, 0.06),
    inset 0 1px 0 rgba(255, 255, 255, 0.8);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.stat-card-enhanced:hover {
  background: rgba(255, 255, 255, 0.92);
  transform: translateY(-4px);
  box-shadow:
    0 12px 40px rgba(0, 0, 0, 0.1),
    inset 0 1px 0 rgba(255, 255, 255, 0.9);
}

.icon-container {
  @apply rounded-xl flex items-center justify-center relative;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.icon-inner {
  @apply text-white;
}

.pulse-ring {
  @apply absolute inset-0 rounded-xl opacity-30;
  animation: pulse-expand 2s ease-out infinite;
}

@keyframes pulse-expand {
  0% {
    transform: scale(1);
    opacity: 0.3;
  }
  100% {
    transform: scale(1.4);
    opacity: 0;
  }
}

.tabular-nums {
  font-variant-numeric: tabular-nums;
}
</style>
