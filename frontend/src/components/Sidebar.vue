<template>
  <aside class="fixed left-0 top-0 h-full w-64 glass-dark p-6 flex flex-col z-50 dark-scroll">
    <!-- Logo -->
    <div class="flex items-center gap-3 mb-10">
      <div class="logo-icon w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center">
        <ShieldCheck class="w-6 h-6 text-white" :stroke-width="2" />
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
        <SettingsIcon class="w-5 h-5" />
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
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from '../stores/app'

// 使用 Lucide 图标
import {
  LayoutDashboard,
  Sparkles,
  MessageSquare,
  Clock,
  SlidersHorizontal,
  Settings,
  ShieldCheck,
} from '../components/icons'

const route = useRoute()
const appStore = useAppStore()

// 图标组件映射
const DashboardIcon = LayoutDashboard
const SmartAuditIcon = Sparkles
const ResultsIcon = MessageSquare
const ScanHistoryIcon = Clock
const RulesIcon = SlidersHorizontal
const SettingsIcon = Settings

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

.nav-item.highlight.active {
  @apply bg-violet-500/15;
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
