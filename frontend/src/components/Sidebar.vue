<template>
  <aside class="fixed left-0 top-0 h-full w-64 glass-dark p-6 flex flex-col z-50 dark-scroll">
    <!-- Logo -->
    <div class="flex items-center gap-3 mb-10">
      <div class="logo-icon w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center">
        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
        </svg>
      </div>
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight">CodeScan</h1>
        <p class="text-xs text-white/50">安全代码审计平台</p>
      </div>
    </div>

    <!-- 导航菜单 -->
    <nav class="flex-1 space-y-1.5">
      <!-- 主菜单项 -->
      <router-link
        v-for="item in mainMenuItems"
        :key="item.path"
        :to="item.path"
        class="nav-item group"
        :class="{ 'active': isActive(item.path), 'highlight': item.highlight }"
      >
        <div class="nav-icon" :class="item.iconBg">
          <component :is="item.icon" class="w-5 h-5" />
        </div>
        <span>{{ item.name }}</span>
        <span v-if="item.badge" class="ml-auto px-2 py-0.5 text-xs rounded-full" :class="item.badgeClass">
          {{ item.badge }}
        </span>
      </router-link>

      <!-- 安全规则 -->
      <router-link
        to="/rules"
        class="nav-item group"
        :class="{ 'active': isActive('/rules') }"
      >
        <div class="nav-icon bg-amber-600">
          <RulesIcon class="w-5 h-5" />
        </div>
        <span>安全规则</span>
      </router-link>
    </nav>

    <!-- 分隔线 -->
    <div class="border-t border-white/10 my-4"></div>

    <!-- 设置入口 -->
    <router-link
      to="/settings"
      class="nav-item group mb-4"
      :class="{ 'active': isActive('/settings') }"
    >
      <div class="nav-icon bg-gray-600">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
        </svg>
      </div>
      <span>系统设置</span>
    </router-link>

    <!-- 状态指示卡片 -->
    <div class="bg-white/10 rounded-2xl p-4 space-y-3">
      <div class="flex items-center gap-3">
        <div class="relative">
          <div class="w-3 h-3 rounded-full" :class="statusColor"></div>
          <div v-if="appStore.isConnected" class="absolute inset-0 rounded-full animate-ping" :class="statusColor" style="animation-duration: 2s;"></div>
        </div>
        <span class="text-sm font-medium text-white/90">{{ statusText }}</span>
      </div>

      <div class="space-y-2">
        <div class="flex justify-between text-xs">
          <span class="text-white/60">代码单元</span>
          <span class="text-white font-medium">{{ formatNumber(stats.totalUnits || 0) }}</span>
        </div>
        <div class="flex justify-between text-xs">
          <span class="text-white/60">已索引文件</span>
          <span class="text-white font-medium">{{ formatNumber(stats.totalFiles || 0) }}</span>
        </div>
      </div>

      <!-- 迷你进度条 -->
      <div v-if="appStore.currentScan" class="pt-2 border-t border-white/10">
        <div class="flex justify-between text-xs mb-1">
          <span class="text-white/60">扫描进度</span>
          <span class="text-white">{{ Math.round(appStore.currentScan.progress * 100) }}%</span>
        </div>
        <div class="progress-bar h-1.5">
          <div class="progress-bar-fill" :style="{ width: `${appStore.currentScan.progress * 100}%` }"></div>
        </div>
      </div>
    </div>
  </aside>
</template>

<script setup>
import { ref, computed, onMounted, h } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from '../stores/app'

const route = useRoute()
const appStore = useAppStore()

// 图标组件
const DashboardIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z' })
  ])
}

const SmartAuditIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' })
  ])
}

const ScanIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' })
  ])
}

const ResultsIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z' })
  ])
}

const RulesIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4' })
  ])
}

const ScanHistoryIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' })
  ])
}

// 主菜单项（精简后的核心功能）
// 移除批量扫描入口，智能审计成为统一入口
const mainMenuItems = [
  { name: '仪表盘', path: '/', icon: DashboardIcon, iconBg: 'bg-blue-600' },
  { name: '智能审计', path: '/audit', icon: SmartAuditIcon, iconBg: 'bg-violet-600', highlight: true },
  { name: '聊天记录', path: '/chat-history', icon: ResultsIcon, iconBg: 'bg-cyan-600' },
  { name: '扫描记录', path: '/scan-history', icon: ScanHistoryIcon, iconBg: 'bg-emerald-600' },
]

const stats = computed(() => appStore.stats)

const statusColor = computed(() => {
  if (appStore.isConnected) return 'bg-green-400'
  return 'bg-red-400'
})

const statusText = computed(() => {
  if (appStore.isConnected) return '服务已连接'
  return '服务未连接'
})

const isActive = (path) => {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

const formatNumber = (num) => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

onMounted(() => {
  // 首次加载时静默检查健康状态（不阻塞渲染）
  appStore.checkHealth()
})
</script>

<style scoped>
.nav-item {
  @apply flex items-center gap-3 px-3 py-2.5 rounded-xl text-white/70 transition-all duration-300;
  position: relative;
  overflow: hidden;
}

/* 左侧边框指示器 */
.nav-item::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%) scaleY(0);
  width: 3px;
  height: 60%;
  border-radius: 0 3px 3px 0;
  background: #007AFF;
  transition: transform 0.2s ease;
}

.nav-item:hover::before {
  transform: translateY(-50%) scaleY(1);
}

.nav-item:hover {
  @apply bg-white/10 text-white;
  transform: translateX(4px);
}

.nav-item.active {
  @apply bg-white/15 text-white font-medium;
  box-shadow:
    0 4px 12px rgba(0, 0, 0, 0.15),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);
}

.nav-item.active::before {
  transform: translateY(-50%) scaleY(1);
}

.nav-item.highlight {
  @apply bg-violet-500/10;
}

.nav-item.highlight:not(.active) {
  @apply bg-violet-500/10;
}

.nav-icon {
  @apply w-8 h-8 rounded-lg flex items-center justify-center text-white;
}

.nav-item.active .nav-icon {
  /* 无特殊效果 */
}

/* Logo 悬停效果 */
.logo-icon {
  transition: transform 0.2s ease;
  cursor: pointer;
}

.logo-icon:hover {
  transform: scale(1.05);
}
</style>
