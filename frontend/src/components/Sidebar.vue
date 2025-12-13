<template>
  <aside class="fixed left-0 top-0 h-full w-64 glass-dark p-6 flex flex-col z-50 dark-scroll">
    <!-- Logo -->
    <div class="flex items-center gap-3 mb-10">
      <div class="w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/30">
        <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
      <router-link
        v-for="item in menuItems"
        :key="item.path"
        :to="item.path"
        class="nav-item group"
        :class="{ 'active': isActive(item.path) }"
      >
        <div class="nav-icon" :class="item.iconBg">
          <component :is="item.icon" class="w-5 h-5" />
        </div>
        <span>{{ item.name }}</span>
        <span v-if="item.badge" class="ml-auto px-2 py-0.5 text-xs rounded-full" :class="item.badgeClass">
          {{ item.badge }}
        </span>
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
      <div class="nav-icon bg-gradient-to-br from-gray-600 to-gray-700">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
        </svg>
      </div>
      <span>系统设置</span>
    </router-link>

    <!-- 状态指示卡片 -->
    <div class="glass rounded-2xl p-4 space-y-3">
      <div class="flex items-center gap-3">
        <div class="relative">
          <div class="w-3 h-3 rounded-full" :class="statusColor"></div>
          <div v-if="appStore.isConnected" class="absolute inset-0 rounded-full animate-ping" :class="statusColor" style="animation-duration: 2s;"></div>
        </div>
        <span class="text-sm font-medium text-white/90">{{ statusText }}</span>
      </div>

      <div class="space-y-2">
        <div class="flex justify-between text-xs">
          <span class="text-white/50">代码单元</span>
          <span class="text-white/80 font-medium">{{ formatNumber(stats.totalUnits || 0) }}</span>
        </div>
        <div class="flex justify-between text-xs">
          <span class="text-white/50">已索引文件</span>
          <span class="text-white/80 font-medium">{{ formatNumber(stats.totalFiles || 0) }}</span>
        </div>
      </div>

      <!-- 迷你进度条 -->
      <div v-if="appStore.currentScan" class="pt-2 border-t border-white/10">
        <div class="flex justify-between text-xs mb-1">
          <span class="text-white/50">扫描进度</span>
          <span class="text-white/80">{{ Math.round(appStore.currentScan.progress * 100) }}%</span>
        </div>
        <div class="progress-bar h-1.5">
          <div class="progress-bar-fill" :style="{ width: `${appStore.currentScan.progress * 100}%` }"></div>
        </div>
      </div>
    </div>
  </aside>
</template>

<script setup>
import { computed, onMounted, h } from 'vue'
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

const ScanIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' })
  ])
}

const ResultsIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' })
  ])
}

const CallGraphIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1' })
  ])
}

const RulesIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4' })
  ])
}

const SearchIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4' })
  ])
}

const CodeGraphIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z' })
  ])
}

const VariantIcon = {
  render: () => h('svg', { fill: 'none', stroke: 'currentColor', viewBox: '0 0 24 24' }, [
    h('path', { 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'stroke-width': '2', d: 'M13 10V3L4 14h7v7l9-11h-7z' })
  ])
}

const menuItems = [
  { name: '仪表盘', path: '/', icon: DashboardIcon, iconBg: 'bg-gradient-to-br from-blue-500 to-blue-600' },
  { name: '开始扫描', path: '/scan', icon: ScanIcon, iconBg: 'bg-gradient-to-br from-green-500 to-emerald-600' },
  { name: '扫描结果', path: '/results', icon: ResultsIcon, iconBg: 'bg-gradient-to-br from-orange-500 to-red-500', badge: appStore.pendingFindings || null, badgeClass: 'bg-red-500/20 text-red-400' },
  { name: '调用链', path: '/callgraph', icon: CallGraphIcon, iconBg: 'bg-gradient-to-br from-purple-500 to-pink-500' },
  { name: '代码图', path: '/code-graph', icon: CodeGraphIcon, iconBg: 'bg-gradient-to-br from-indigo-500 to-purple-600' },
  { name: '变体分析', path: '/variant-analysis', icon: VariantIcon, iconBg: 'bg-gradient-to-br from-rose-500 to-red-600' },
  { name: '安全规则', path: '/rules', icon: RulesIcon, iconBg: 'bg-gradient-to-br from-yellow-500 to-orange-500' },
  { name: '代码搜索', path: '/search', icon: SearchIcon, iconBg: 'bg-gradient-to-br from-cyan-500 to-blue-500' },
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
  appStore.fetchStats()
  appStore.checkHealth()
})
</script>

<style scoped>
.nav-item {
  @apply flex items-center gap-3 px-3 py-2.5 rounded-xl text-white/70 transition-all duration-300;
}

.nav-item:hover {
  @apply bg-white/10 text-white;
}

.nav-item.active {
  @apply bg-white/15 text-white font-medium;
  box-shadow:
    0 4px 12px rgba(0, 0, 0, 0.15),
    inset 0 1px 0 rgba(255, 255, 255, 0.1);
}

.nav-icon {
  @apply w-9 h-9 rounded-xl flex items-center justify-center text-white shadow-lg transition-transform duration-300;
}

.nav-item:hover .nav-icon {
  @apply scale-110;
}

.nav-item.active .nav-icon {
  @apply scale-105;
}
</style>
