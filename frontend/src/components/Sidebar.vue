<template>
  <aside class="fixed left-0 top-0 h-full w-64 glass-dark p-6 flex flex-col z-50 dark-scroll">
    <!-- Logo -->
    <div class="flex items-center gap-3 mb-10">
      <div class="logo-icon w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/30">
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
        <span v-if="item.isPrimary" class="ml-auto flex items-center">
          <span class="nav-pulse-dot"></span>
        </span>
      </router-link>

      <!-- 高级工具子菜单 -->
      <div class="mt-2">
        <button
          @click="toggleAdvancedMenu"
          class="nav-item group w-full justify-between"
          :class="{ 'active': isAdvancedActive }"
        >
          <div class="flex items-center gap-3">
            <div class="nav-icon bg-gradient-to-br from-slate-500 to-slate-600">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/>
              </svg>
            </div>
            <span>高级工具</span>
          </div>
          <svg
            class="w-4 h-4 text-white/50 transition-transform duration-300"
            :class="{ 'rotate-180': isAdvancedMenuOpen }"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
          </svg>
        </button>

        <!-- 子菜单项 -->
        <transition
          enter-active-class="transition-all duration-300 ease-out"
          leave-active-class="transition-all duration-200 ease-in"
          enter-from-class="opacity-0 max-h-0"
          enter-to-class="opacity-100 max-h-96"
          leave-from-class="opacity-100 max-h-96"
          leave-to-class="opacity-0 max-h-0"
        >
          <div v-if="isAdvancedMenuOpen" class="ml-4 mt-1 space-y-1 overflow-hidden">
            <router-link
              v-for="item in advancedMenuItems"
              :key="item.path"
              :to="item.path"
              class="nav-item-sub group"
              :class="{ 'active': isActive(item.path) }"
            >
              <div class="nav-icon-sub" :class="item.iconBg">
                <component :is="item.icon" class="w-4 h-4" />
              </div>
              <span>{{ item.name }}</span>
            </router-link>
          </div>
        </transition>
      </div>

      <!-- 安全规则 -->
      <router-link
        to="/rules"
        class="nav-item group"
        :class="{ 'active': isActive('/rules') }"
      >
        <div class="nav-icon bg-gradient-to-br from-yellow-500 to-orange-500">
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
      <div class="nav-icon bg-gradient-to-br from-gray-600 to-gray-700">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
        </svg>
      </div>
      <span>系统设置</span>
    </router-link>

    <!-- 状态指示卡片 -->
    <div class="glass rounded-2xl p-4 space-y-3 status-card-breathe">
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
import { ref, computed, onMounted, h } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from '../stores/app'

const route = useRoute()
const appStore = useAppStore()

// 子菜单状态
const isAdvancedMenuOpen = ref(false)

const toggleAdvancedMenu = () => {
  isAdvancedMenuOpen.value = !isAdvancedMenuOpen.value
}

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

// 主菜单项（精简后的核心功能）
// 移除批量扫描入口，智能审计成为统一入口
const mainMenuItems = [
  { name: '仪表盘', path: '/', icon: DashboardIcon, iconBg: 'bg-gradient-to-br from-blue-500 to-blue-600' },
  { name: '智能审计', path: '/audit', icon: SmartAuditIcon, iconBg: 'bg-gradient-to-br from-violet-500 to-purple-600', highlight: true, isPrimary: true },
  { name: '聊天记录', path: '/chat-history', icon: ResultsIcon, iconBg: 'bg-gradient-to-br from-cyan-500 to-blue-500' },
]

// 高级工具子菜单
const advancedMenuItems = [
  { name: '调用链分析', path: '/callgraph', icon: CallGraphIcon, iconBg: 'bg-gradient-to-br from-purple-500 to-pink-500' },
  { name: '代码结构图', path: '/code-graph', icon: CodeGraphIcon, iconBg: 'bg-gradient-to-br from-indigo-500 to-purple-600' },
  { name: '变体分析', path: '/variant-analysis', icon: VariantIcon, iconBg: 'bg-gradient-to-br from-rose-500 to-red-600' },
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

// 检查高级工具是否有活动项
const isAdvancedActive = computed(() => {
  return advancedMenuItems.some(item => route.path.startsWith(item.path))
})

// 当高级工具的子路由激活时，自动展开菜单
if (isAdvancedActive.value) {
  isAdvancedMenuOpen.value = true
}

const formatNumber = (num) => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

onMounted(() => {
  // 不再主动调用 API，依赖 Dashboard 或其他页面的调用
  // Store 已实现请求去重和缓存，即使多处调用也只发一次请求
  // 首次加载时静默检查健康状态（不阻塞渲染）
  appStore.checkHealth()

  // 如果当前路由在高级工具中，展开菜单
  if (isAdvancedActive.value) {
    isAdvancedMenuOpen.value = true
  }
})
</script>

<style scoped>
.nav-item {
  @apply flex items-center gap-3 px-3 py-2.5 rounded-xl text-white/70 transition-all duration-300;
  position: relative;
  overflow: hidden;
}

/* 左侧渐变边框指示器 */
.nav-item::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%) scaleY(0);
  width: 3px;
  height: 60%;
  border-radius: 0 3px 3px 0;
  background: linear-gradient(180deg, #007AFF 0%, #5856D6 100%);
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
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
  @apply ring-1 ring-violet-400/30;
  animation: highlight-breathe 3s ease-in-out infinite;
}

.nav-item.highlight:not(.active) {
  @apply bg-violet-500/10;
}

@keyframes highlight-breathe {
  0%, 100% {
    background: rgba(139, 92, 246, 0.08);
    box-shadow: 0 0 0 1px rgba(167, 139, 250, 0.3);
  }
  50% {
    background: rgba(139, 92, 246, 0.15);
    box-shadow: 0 0 12px 1px rgba(167, 139, 250, 0.4);
  }
}

.nav-icon {
  @apply w-9 h-9 rounded-xl flex items-center justify-center text-white shadow-lg;
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s ease;
  position: relative;
}

/* 图标发光效果 */
.nav-icon::after {
  content: '';
  position: absolute;
  inset: -4px;
  border-radius: inherit;
  background: inherit;
  filter: blur(12px);
  opacity: 0;
  transition: opacity 0.3s ease;
  z-index: -1;
}

.nav-item:hover .nav-icon {
  transform: scale(1.1) rotate(3deg);
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
}

.nav-item:hover .nav-icon::after {
  opacity: 0.5;
}

.nav-item.active .nav-icon {
  @apply scale-105;
}

/* 脉冲光点样式 */
.nav-pulse-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: linear-gradient(135deg, #8B5CF6 0%, #A855F7 100%);
  box-shadow: 0 0 10px rgba(139, 92, 246, 0.6);
  animation: nav-pulse 2s ease-in-out infinite;
}

@keyframes nav-pulse {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
    box-shadow: 0 0 10px rgba(139, 92, 246, 0.6);
  }
  50% {
    opacity: 0.7;
    transform: scale(1.3);
    box-shadow: 0 0 20px rgba(139, 92, 246, 0.8);
  }
}

/* 子菜单样式 */
.nav-item-sub {
  @apply flex items-center gap-2.5 px-3 py-2 rounded-lg text-white/60 text-sm transition-all duration-200;
  position: relative;
}

.nav-item-sub::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%) scaleY(0);
  width: 2px;
  height: 50%;
  border-radius: 0 2px 2px 0;
  background: linear-gradient(180deg, #8B5CF6 0%, #EC4899 100%);
  transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

.nav-item-sub:hover::before {
  transform: translateY(-50%) scaleY(1);
}

.nav-item-sub:hover {
  @apply bg-white/10 text-white/90;
  transform: translateX(3px);
}

.nav-item-sub.active {
  @apply bg-white/15 text-white font-medium;
}

.nav-item-sub.active::before {
  transform: translateY(-50%) scaleY(1);
}

.nav-icon-sub {
  @apply w-7 h-7 rounded-lg flex items-center justify-center text-white/90 shadow transition-all duration-200;
}

.nav-item-sub:hover .nav-icon-sub {
  transform: scale(1.08) rotate(2deg);
}

/* Logo 悬停效果 */
.logo-icon {
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s ease;
  cursor: pointer;
}

.logo-icon:hover {
  transform: scale(1.05) rotate(-3deg);
  box-shadow: 0 12px 28px rgba(59, 130, 246, 0.4);
}
</style>
