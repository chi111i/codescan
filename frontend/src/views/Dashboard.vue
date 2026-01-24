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
          <RefreshCw :class="{ 'animate-spin': loading }" class="w-4 h-4" />
          {{ loading ? '刷新中...' : '刷新' }}
        </button>
        <router-link to="/audit" class="btn-primary flex items-center gap-2">
          <Sparkles class="w-4 h-4" />
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
      <!-- 漏洞统计卡片 -->
      <div class="content-card">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-base font-medium text-gray-900">漏洞统计</h2>
          <router-link
            v-if="totalFindings > 0"
            to="/scan-history"
            class="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1"
          >
            查看全部
            <ChevronRight class="w-3 h-3" />
          </router-link>
        </div>

        <!-- 总数展示 -->
        <div class="text-center py-4 mb-4">
          <div class="text-4xl font-bold" :class="totalFindings > 0 ? 'text-orange-600' : 'text-gray-900'">
            {{ totalFindings }}
          </div>
          <div class="text-sm text-gray-500 mt-1">已发现问题</div>
        </div>

        <!-- 严重级别统计 -->
        <div class="space-y-3">
          <div v-for="item in severityStats" :key="item.level" class="severity-stat-item">
            <div class="flex items-center justify-between mb-1.5">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full" :class="item.dotClass"></span>
                <span class="text-sm text-gray-600">{{ item.label }}</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-sm font-semibold" :class="item.textClass">{{ item.count }}</span>
                <span class="text-xs text-gray-400 w-8 text-right">{{ item.percentage }}%</span>
              </div>
            </div>
            <div class="h-1.5 bg-gray-100 rounded-full overflow-hidden">
              <div
                class="h-full rounded-full transition-all duration-500"
                :class="item.barClass"
                :style="{ width: `${item.percentage}%` }"
              ></div>
            </div>
          </div>

          <!-- 空状态 -->
          <div v-if="totalFindings === 0" class="text-center py-6">
            <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-green-50 flex items-center justify-center">
              <ShieldCheck class="w-6 h-6 text-green-500" />
            </div>
            <p class="text-sm text-gray-500">暂无安全问题</p>
            <p class="text-xs text-gray-400 mt-1">代码安全状况良好</p>
          </div>
        </div>
      </div>

      <!-- 最近发现卡片 -->
      <div class="content-card">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-base font-medium text-gray-900">最近发现</h2>
          <router-link
            v-if="recentFindings.length > 0"
            to="/scan-history"
            class="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1"
          >
            查看全部
            <ChevronRight class="w-3 h-3" />
          </router-link>
        </div>

        <!-- 发现列表 -->
        <div v-if="recentFindings.length > 0" class="space-y-2">
          <div
            v-for="finding in recentFindings"
            :key="finding.id"
            class="finding-item group"
            @click="viewFinding(finding)"
          >
            <div class="flex items-center gap-3 min-w-0 flex-1">
              <!-- 严重级别指示器 -->
              <span
                class="flex-shrink-0 w-1.5 h-8 rounded-full"
                :class="getSeverityBarClass(finding.severity)"
              ></span>

              <!-- 内容区 -->
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2 mb-0.5">
                  <span
                    class="text-xs font-medium px-1.5 py-0.5 rounded"
                    :class="getSeverityBadgeClass(finding.severity)"
                  >
                    {{ getSeverityLabel(finding.severity) }}
                  </span>
                  <span class="text-sm font-medium text-gray-900 truncate">
                    {{ finding.vuln_type || finding.category || finding.title || finding.name || finding.issue_type || finding.type || '未知类型' }}
                  </span>
                </div>
                <div class="flex items-center gap-2 text-xs text-gray-500">
                  <span class="truncate max-w-[140px]" :title="finding.file_path">
                    {{ truncatePath(finding.file_path) }}
                  </span>
                  <span class="text-gray-300">|</span>
                  <span class="flex-shrink-0">{{ formatRelativeTime(finding.created_at) }}</span>
                </div>
              </div>
            </div>

            <!-- 箭头指示 -->
            <ChevronRight class="w-4 h-4 text-gray-300 group-hover:text-gray-500 transition-colors flex-shrink-0" />
          </div>
        </div>

        <!-- 空状态 -->
        <div v-else class="text-center py-8">
          <div class="w-14 h-14 mx-auto mb-3 rounded-full bg-gray-50 flex items-center justify-center">
            <ClipboardCheck class="w-7 h-7 text-gray-300" />
          </div>
          <p class="text-sm text-gray-500">暂无安全发现</p>
          <p class="text-xs text-gray-400 mt-1">开始扫描以检测潜在漏洞</p>
          <router-link
            to="/audit"
            class="inline-flex items-center gap-1.5 mt-3 text-xs text-blue-600 hover:text-blue-700"
          >
            <Search class="w-3.5 h-3.5" />
            开始审计
          </router-link>
        </div>
      </div>

      <!-- 安全规则卡片 -->
      <div class="content-card flex flex-col">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-base font-medium text-gray-900">安全规则</h2>
          <router-link
            to="/rules"
            class="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1"
          >
            管理规则
            <ChevronRight class="w-3 h-3" />
          </router-link>
        </div>

        <!-- 总数展示 -->
        <div class="text-center py-4 mb-4">
          <div class="text-4xl font-bold text-green-600">{{ rulesCount }}</div>
          <div class="text-sm text-gray-500 mt-1">条检测规则</div>
        </div>

        <!-- 类别标签 -->
        <div class="flex-1">
          <div v-if="ruleCategories.length > 0" class="flex flex-wrap gap-2">
            <router-link
              v-for="category in ruleCategories"
              :key="category.name"
              :to="`/rules?category=${category.name}`"
              class="rule-category-tag"
              :class="getCategoryColorClass(category.name)"
            >
              <span class="font-medium">{{ category.label }}</span>
              <span class="opacity-75">{{ category.count }}</span>
            </router-link>
          </div>

          <!-- 空状态 -->
          <div v-else class="text-center py-6">
            <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-gray-50 flex items-center justify-center">
              <ClipboardList class="w-6 h-6 text-gray-300" />
            </div>
            <p class="text-sm text-gray-500">暂无规则数据</p>
          </div>
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
              <Check v-if="scan.status === 'completed'" class="w-4 h-4 text-green-600" />
              <RefreshCw v-else-if="scan.status === 'analyzing' || scan.status === 'indexing'" class="w-4 h-4 text-blue-600 animate-spin" />
              <X v-else-if="scan.status === 'failed'" class="w-4 h-4 text-red-600" />
              <Clock v-else class="w-4 h-4 text-gray-400" />
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
            <ChevronRight class="w-4 h-4 text-gray-400" />
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

// 使用 Lucide 图标
import {
  RefreshCw,
  Sparkles,
  ChevronRight,
  ShieldCheck,
  ClipboardCheck,
  ClipboardList,
  Search,
  Check,
  X,
  Clock,
} from '../components/icons'

const router = useRouter()
const appStore = useAppStore()

const loading = ref(false)
const stats = computed(() => appStore.stats)
const scanHistory = computed(() => appStore.scanHistory)
const recentFindings = computed(() => appStore.recentFindings)
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
      dotClass: 'bg-red-500',
      textClass: 'text-red-600',
      barClass: 'bg-red-500',
    },
    {
      level: 'high',
      label: '高危',
      count: high,
      percentage: Math.round((high / total) * 100),
      dotClass: 'bg-orange-500',
      textClass: 'text-orange-600',
      barClass: 'bg-orange-500',
    },
    {
      level: 'medium',
      label: '中危',
      count: medium,
      percentage: Math.round((medium / total) * 100),
      dotClass: 'bg-yellow-500',
      textClass: 'text-yellow-600',
      barClass: 'bg-yellow-500',
    },
    {
      level: 'low',
      label: '低危',
      count: low,
      percentage: Math.round((low / total) * 100),
      dotClass: 'bg-blue-500',
      textClass: 'text-blue-600',
      barClass: 'bg-blue-500',
    },
  ]
})

// 规则类别统计
const ruleCategories = computed(() => {
  if (!appStore.rules || appStore.rules.length === 0) return []

  const categoryMap = {}
  appStore.rules.forEach(rule => {
    const cat = rule.category || 'other'
    if (!categoryMap[cat]) {
      categoryMap[cat] = { name: cat, count: 0 }
    }
    categoryMap[cat].count++
  })

  // 类别标签映射
  const labelMap = {
    rce: 'RCE',
    command_injection: 'RCE',
    sql_injection: 'SQLi',
    sqli: 'SQLi',
    ssrf: 'SSRF',
    file_read: 'File',
    file_write: 'File',
    file_upload: 'File',
    path_traversal: 'File',
    auth: 'Auth',
    authentication: 'Auth',
    authorization: 'Auth',
    xss: 'XSS',
    crypto: 'Crypto',
    deserialization: 'Deser',
    xxe: 'XXE',
    other: '其他',
  }

  return Object.values(categoryMap)
    .map(cat => ({
      ...cat,
      label: labelMap[cat.name] || cat.name.toUpperCase(),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)
})

// 严重级别样式映射
const getSeverityBarClass = (severity) => {
  const classes = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
  }
  return classes[severity] || 'bg-gray-400'
}

const getSeverityBadgeClass = (severity) => {
  const classes = {
    critical: 'bg-red-50 text-red-700',
    high: 'bg-orange-50 text-orange-700',
    medium: 'bg-yellow-50 text-yellow-700',
    low: 'bg-blue-50 text-blue-700',
  }
  return classes[severity] || 'bg-gray-50 text-gray-700'
}

const getSeverityLabel = (severity) => {
  const labels = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return labels[severity] || severity
}

// 路径截断
const truncatePath = (path) => {
  if (!path) return ''
  const parts = path.split(/[/\\]/)
  if (parts.length <= 2) return path
  return '.../' + parts.slice(-2).join('/')
}

// 相对时间格式化
const formatRelativeTime = (dateString) => {
  if (!dateString) return ''
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now - date
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return '刚刚'
  if (diffMins < 60) return `${diffMins}分钟前`
  if (diffHours < 24) return `${diffHours}小时前`
  if (diffDays < 7) return `${diffDays}天前`
  return date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' })
}

// 查看发现详情
const viewFinding = (finding) => {
  router.push({ path: '/scan-history', query: { scan_id: finding.scan_id, finding: finding.id } })
}

// 类别颜色映射
const getCategoryColorClass = (category) => {
  const colorMap = {
    rce: 'bg-red-50 text-red-700 hover:bg-red-100',
    command_injection: 'bg-red-50 text-red-700 hover:bg-red-100',
    sql_injection: 'bg-orange-50 text-orange-700 hover:bg-orange-100',
    sqli: 'bg-orange-50 text-orange-700 hover:bg-orange-100',
    ssrf: 'bg-purple-50 text-purple-700 hover:bg-purple-100',
    file_read: 'bg-yellow-50 text-yellow-700 hover:bg-yellow-100',
    file_write: 'bg-yellow-50 text-yellow-700 hover:bg-yellow-100',
    auth: 'bg-blue-50 text-blue-700 hover:bg-blue-100',
    xss: 'bg-green-50 text-green-700 hover:bg-green-100',
    crypto: 'bg-indigo-50 text-indigo-700 hover:bg-indigo-100',
  }
  return colorMap[category] || 'bg-gray-50 text-gray-700 hover:bg-gray-100'
}

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
      appStore.fetchRecentFindings(5),  // 获取最近5个发现
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

/* 发现列表项 */
.finding-item {
  @apply flex items-center justify-between p-2.5 rounded-lg hover:bg-gray-50 cursor-pointer transition-colors;
}

/* 规则类别标签 */
.rule-category-tag {
  @apply inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs transition-colors;
}

/* 扫描列表项 */
.scan-item {
  @apply flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 cursor-pointer transition;
}

.status-icon {
  @apply w-8 h-8 rounded-lg flex items-center justify-center;
}

/* 旋转动画 */
.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
