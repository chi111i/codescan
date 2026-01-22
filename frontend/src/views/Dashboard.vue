<template>
  <div class="space-y-6">
    <!-- 页面标题 -->
    <div class="flex justify-between items-center">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900">仪表盘</h1>
        <p class="text-gray-500 text-sm mt-1">代码安全审计概览</p>
      </div>
      <div class="flex items-center gap-3">
        <button @click="refreshData" :disabled="loading" class="btn-secondary flex items-center gap-2">
          <svg :class="{ 'spinner': loading }" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          {{ loading ? '刷新中...' : '刷新' }}
        </button>
        <router-link to="/audit" class="btn-primary flex items-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
          </svg>
          开始审计
        </router-link>
      </div>
    </div>

    <!-- 索引进度条 -->
    <IndexProgressBar
      v-if="appStore.indexProgress"
      :progress="appStore.indexProgress"
      :visible="!!appStore.indexProgress"
      @close="appStore.closeIndexProgress()"
    />

    <!-- 摘要区域 - 整合统计信息 -->
    <div class="summary-card">
      <div class="grid grid-cols-2 md:grid-cols-4 divide-x divide-gray-200">
        <div class="summary-item">
          <span class="summary-value">{{ formatNumber(stats.totalUnits || 0) }}</span>
          <span class="summary-label">代码单元</span>
        </div>
        <div class="summary-item">
          <span class="summary-value">{{ scanHistory.length }}</span>
          <span class="summary-label">扫描任务</span>
        </div>
        <div class="summary-item">
          <span class="summary-value" :class="totalFindings > 0 ? 'text-orange-600' : ''">{{ totalFindings }}</span>
          <span class="summary-label">发现问题</span>
        </div>
        <div class="summary-item">
          <span class="summary-value text-green-600">{{ rulesCount }}</span>
          <span class="summary-label">安全规则</span>
        </div>
      </div>
    </div>

    <!-- 安全状态概览 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 安全评分 - 简化版 -->
      <div class="content-card">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-base font-medium text-gray-900">安全评分</h2>
          <span class="score-badge" :class="scoreTagClass">{{ scoreLabel }}</span>
        </div>
        <div class="flex items-center gap-6">
          <div class="score-ring">
            <svg class="w-20 h-20 transform -rotate-90">
              <circle cx="40" cy="40" r="32" fill="none" stroke="#e5e7eb" stroke-width="6"/>
              <circle
                cx="40" cy="40" r="32"
                fill="none"
                :stroke="scoreColor"
                stroke-width="6"
                stroke-linecap="round"
                :stroke-dasharray="`${securityScore * 2.01} 201`"
                class="transition-all duration-700"
              />
            </svg>
            <span class="score-text" :class="scoreTextClass">{{ securityScore }}</span>
          </div>
          <div class="flex-1 space-y-2">
            <div v-for="item in severityStats" :key="item.level" class="severity-bar">
              <div class="flex justify-between text-xs mb-1">
                <span class="text-gray-600">{{ item.label }}</span>
                <span :class="item.textClass">{{ item.count }}</span>
              </div>
              <div class="h-1.5 bg-gray-100 rounded-full overflow-hidden">
                <div class="h-full rounded-full transition-all duration-500" :class="item.barClass" :style="{ width: `${item.percentage}%` }"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 语言分布 -->
      <div class="content-card">
        <h2 class="text-base font-medium text-gray-900 mb-4">语言分布</h2>
        <div class="space-y-3">
          <div v-for="(count, lang) in stats.languages" :key="lang" class="flex items-center gap-3">
            <div class="w-2 h-2 rounded-full" :class="getLangDotColor(lang)"></div>
            <span class="text-sm text-gray-700 capitalize flex-1">{{ lang }}</span>
            <span class="text-sm font-medium text-gray-900">{{ count }}</span>
            <span class="text-xs text-gray-400">{{ getPercentage(count) }}%</span>
          </div>
          <div v-if="Object.keys(stats.languages || {}).length === 0" class="text-center py-6 text-gray-400 text-sm">
            暂无索引数据
          </div>
        </div>
      </div>

      <!-- 索引项目入口 -->
      <div class="content-card flex flex-col">
        <h2 class="text-base font-medium text-gray-900 mb-4">快速开始</h2>
        <div class="flex-1 flex flex-col justify-center space-y-3">
          <button @click="showIndexDialog = true" class="quick-action-btn">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
            </svg>
            <span>索引项目</span>
          </button>
          <router-link to="/audit" class="quick-action-btn">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
            <span>智能审计</span>
          </router-link>
        </div>
      </div>
    </div>

    <!-- 最近扫描 -->
    <div class="content-card">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-base font-medium text-gray-900">最近扫描</h2>
        <router-link to="/scan-history" class="text-sm text-blue-600 hover:text-blue-700">
          查看全部 →
        </router-link>
      </div>

      <div class="space-y-2">
        <div
          v-for="scan in recentScans"
          :key="scan.scan_id"
          class="scan-item"
          @click="viewScan(scan.scan_id)"
        >
          <div class="flex items-center gap-3 min-w-0">
            <div class="status-icon" :class="getStatusBgColor(scan.status)">
              <svg v-if="scan.status === 'completed'" class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              <svg v-else-if="scan.status === 'analyzing' || scan.status === 'indexing'" class="w-4 h-4 text-blue-600 spinner" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
              </svg>
              <svg v-else-if="scan.status === 'failed'" class="w-4 h-4 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
              <svg v-else class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </div>
            <div class="min-w-0">
              <div class="text-sm font-medium text-gray-900 truncate">{{ getFileName(scan.target_path) }}</div>
              <div class="text-xs text-gray-500">{{ formatDate(scan.started_at) }}</div>
            </div>
          </div>
          <div class="flex items-center gap-4">
            <span class="text-xs px-2 py-0.5 rounded-full" :class="getStatusTagClass(scan.status)">
              {{ getStatusLabel(scan.status) }}
            </span>
            <div class="text-sm font-medium text-gray-700">
              {{ scan.findings_count + scan.vuln_count }} <span class="text-gray-400 font-normal">问题</span>
            </div>
            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
            </svg>
          </div>
        </div>

        <div v-if="scanHistory.length === 0" class="text-center py-8 text-gray-400 text-sm">
          暂无扫描记录
        </div>
      </div>
    </div>

    <!-- 索引项目对话框 -->
    <div v-if="showIndexDialog" class="fixed inset-0 bg-black/30 flex items-center justify-center z-50" @click.self="showIndexDialog = false">
      <div class="bg-white rounded-2xl p-6 w-full max-w-md mx-4 shadow-xl">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">索引项目</h3>
        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">项目路径</label>
            <input
              v-model="indexPath"
              type="text"
              placeholder="输入项目目录路径..."
              class="w-full px-4 py-2.5 rounded-lg border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 outline-none transition"
            />
          </div>
          <label class="flex items-center gap-2 text-sm text-gray-600">
            <input v-model="clearExisting" type="checkbox" class="w-4 h-4 text-blue-600 rounded border-gray-300"/>
            清空现有索引
          </label>
        </div>
        <div class="flex justify-end gap-3 mt-6">
          <button @click="showIndexDialog = false" class="px-4 py-2 rounded-lg text-gray-600 hover:bg-gray-100 transition">
            取消
          </button>
          <button
            @click="startIndex"
            :disabled="!indexPath || indexing"
            class="px-4 py-2 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {{ indexing ? '索引中...' : '开始索引' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
// 组件名称 - 用于 keep-alive 缓存匹配
defineOptions({ name: 'Dashboard' })

import { ref, computed, onMounted, onActivated } from 'vue'
import { useRouter } from 'vue-router'
import { useAppStore } from '../stores/app'
import IndexProgressBar from '../components/IndexProgressBar.vue'

const router = useRouter()
const appStore = useAppStore()

const loading = ref(false)
const stats = computed(() => appStore.stats)
const scanHistory = computed(() => appStore.scanHistory)
const rulesCount = ref(0)

// 索引对话框状态
const showIndexDialog = ref(false)
const indexPath = ref('')
const clearExisting = ref(false)
const indexing = ref(false)

// 格式化数字
const formatNumber = (num) => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

// 开始索引
const startIndex = async () => {
  if (!indexPath.value) return

  indexing.value = true
  showIndexDialog.value = false

  try {
    await appStore.startAsyncIndex({
      target_path: indexPath.value,
      clear_existing: clearExisting.value,
    })
  } catch (error) {
    console.error('索引失败:', error)
    alert('索引启动失败: ' + (error.message || '未知错误'))
  } finally {
    indexing.value = false
  }
}

const recentScans = computed(() => {
  return [...scanHistory.value]
    .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
    .slice(0, 5)
})

const totalFindings = computed(() => {
  // 使用严重性统计的总和
  return scanHistory.value.reduce((sum, s) =>
    sum + (s.critical_count || 0) + (s.high_count || 0) + (s.medium_count || 0) + (s.low_count || 0), 0
  )
})

const criticalCount = computed(() => {
  return scanHistory.value.reduce((sum, s) => sum + (s.critical_count || 0), 0)
})

// 安全评分计算（添加边界检查）
const securityScore = computed(() => {
  if (!scanHistory.value || scanHistory.value.length === 0) return 100
  if (totalFindings.value === 0) return 100
  const critical = criticalCount.value
  const total = totalFindings.value
  // 简单算法：基础分100，每个问题扣分，critical扣更多
  const score = 100 - (critical * 10) - ((total - critical) * 2)
  return Math.max(0, Math.min(100, Math.round(score)))
})

const scoreColor = computed(() => {
  if (securityScore.value >= 80) return '#34C759'
  if (securityScore.value >= 60) return '#FF9500'
  if (securityScore.value >= 40) return '#FF9500'
  return '#FF3B30'
})

const scoreTextClass = computed(() => {
  if (securityScore.value >= 80) return 'text-green-600'
  if (securityScore.value >= 60) return 'text-orange-500'
  return 'text-red-500'
})

const scoreTagClass = computed(() => {
  if (securityScore.value >= 80) return 'bg-green-100 text-green-700'
  if (securityScore.value >= 60) return 'bg-orange-100 text-orange-700'
  return 'bg-red-100 text-red-700'
})

const scoreLabel = computed(() => {
  if (securityScore.value >= 80) return '安全状况良好'
  if (securityScore.value >= 60) return '存在风险'
  if (securityScore.value >= 40) return '需要关注'
  return '高风险'
})

// 严重性统计
const severityStats = computed(() => {
  const critical = criticalCount.value
  const high = scanHistory.value.reduce((sum, s) => sum + (s.high_count || 0), 0)
  const medium = scanHistory.value.reduce((sum, s) => sum + (s.medium_count || 0), 0)
  const low = scanHistory.value.reduce((sum, s) => sum + (s.low_count || 0), 0)
  const total = critical + high + medium + low || 1

  return [
    {
      level: 'critical',
      label: '严重',
      count: critical,
      percentage: Math.round((critical / total) * 100),
      bgClass: 'bg-red-50 hover:bg-red-100',
      textClass: 'text-red-600',
      barClass: 'bg-gradient-to-r from-red-500 to-red-400',
    },
    {
      level: 'high',
      label: '高危',
      count: high,
      percentage: Math.round((high / total) * 100),
      bgClass: 'bg-orange-50 hover:bg-orange-100',
      textClass: 'text-orange-600',
      barClass: 'bg-gradient-to-r from-orange-500 to-orange-400',
    },
    {
      level: 'medium',
      label: '中危',
      count: medium,
      percentage: Math.round((medium / total) * 100),
      bgClass: 'bg-yellow-50 hover:bg-yellow-100',
      textClass: 'text-yellow-600',
      barClass: 'bg-gradient-to-r from-yellow-500 to-yellow-400',
    },
    {
      level: 'low',
      label: '低危',
      count: low,
      percentage: Math.round((low / total) * 100),
      bgClass: 'bg-blue-50 hover:bg-blue-100',
      textClass: 'text-blue-600',
      barClass: 'bg-gradient-to-r from-blue-500 to-blue-400',
    },
  ]
})

const getPercentage = (count) => {
  const total = stats.value?.totalUnits || 1
  if (total === 0) return 0
  return Math.round((count / total) * 100)
}

const getLangDotColor = (lang) => {
  const colors = {
    python: 'bg-blue-500',
    javascript: 'bg-yellow-500',
    typescript: 'bg-blue-600',
    php: 'bg-purple-500',
    java: 'bg-red-500',
    go: 'bg-cyan-500',
  }
  return colors[lang] || 'bg-gray-500'
}

const getLangBarColor = (lang) => {
  const colors = {
    python: 'bg-gradient-to-r from-blue-500 to-blue-400',
    javascript: 'bg-gradient-to-r from-yellow-500 to-yellow-400',
    typescript: 'bg-gradient-to-r from-blue-600 to-blue-500',
    php: 'bg-gradient-to-r from-purple-500 to-purple-400',
    java: 'bg-gradient-to-r from-red-500 to-red-400',
    go: 'bg-gradient-to-r from-cyan-500 to-cyan-400',
  }
  return colors[lang] || 'bg-gradient-to-r from-gray-500 to-gray-400'
}

const getStatusBgColor = (status) => {
  const colors = {
    completed: 'bg-green-100',
    analyzing: 'bg-blue-100',
    indexing: 'bg-yellow-100',
    pending: 'bg-gray-100',
    failed: 'bg-red-100',
  }
  return colors[status] || 'bg-gray-100'
}

const getStatusTextColor = (status) => {
  const colors = {
    completed: 'text-green-600',
    analyzing: 'text-blue-600',
    indexing: 'text-yellow-600',
    pending: 'text-gray-500',
    failed: 'text-red-600',
  }
  return colors[status] || 'text-gray-500'
}

const getStatusLabel = (status) => {
  const labels = {
    completed: '已完成',
    analyzing: '分析中',
    indexing: '索引中',
    pending: '等待中',
    failed: '失败',
  }
  return labels[status] || status
}

const getStatusTagClass = (status) => {
  const classes = {
    completed: 'bg-green-100 text-green-700',
    analyzing: 'bg-blue-100 text-blue-700',
    indexing: 'bg-yellow-100 text-yellow-700',
    pending: 'bg-gray-100 text-gray-600',
    failed: 'bg-red-100 text-red-700',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
}

const getFileName = (path) => {
  if (!path) return '未知项目'
  const parts = path.split(/[/\\]/)
  return parts[parts.length - 1] || parts[parts.length - 2] || path
}

const formatDate = (dateStr) => {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

const viewScan = (scanId) => {
  router.push({ path: '/scan-history', query: { scan_id: scanId } })
}

const filterBySeverity = (level) => {
  router.push(`/chat-history`)
}

const refreshData = async () => {
  loading.value = true
  try {
    await Promise.all([
      appStore.fetchStats(),
      appStore.fetchScanHistory(),
      appStore.fetchRules(),
    ])
    rulesCount.value = appStore.rules.length
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await refreshData()
})

// keep-alive 激活时刷新数据
onActivated(async () => {
  await refreshData()
})
</script>

<style scoped>
/* 摘要卡片 */
.summary-card {
  @apply bg-white rounded-xl border border-gray-200 overflow-hidden;
}

.summary-item {
  @apply flex flex-col items-center justify-center py-5 px-4;
}

.summary-value {
  @apply text-2xl font-semibold text-gray-900;
}

.summary-label {
  @apply text-xs text-gray-500 mt-1;
}

/* 内容卡片 */
.content-card {
  @apply bg-white rounded-xl border border-gray-200 p-5;
}

/* 安全评分环 */
.score-ring {
  @apply relative flex items-center justify-center;
}

.score-text {
  @apply absolute text-2xl font-bold;
}

.score-badge {
  @apply text-xs px-2 py-0.5 rounded-full font-medium;
}

/* 快速操作按钮 */
.quick-action-btn {
  @apply flex items-center gap-3 px-4 py-3 rounded-lg border border-gray-200 text-gray-700 hover:bg-gray-50 hover:border-gray-300 transition text-sm font-medium;
}

/* 扫描列表项 */
.scan-item {
  @apply flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 cursor-pointer transition;
}

.status-icon {
  @apply w-8 h-8 rounded-lg flex items-center justify-center;
}
</style>
