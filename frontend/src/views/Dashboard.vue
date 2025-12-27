<template>
  <div class="space-y-6">
    <!-- 页面标题 -->
    <div class="flex justify-between items-center">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2">仪表盘</h1>
        <p class="text-white/60">代码安全审计概览</p>
      </div>
      <div class="flex items-center gap-3">
        <button @click="refreshData" :disabled="loading" class="btn-secondary flex items-center gap-2">
          <svg :class="{ 'spinner': loading }" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          {{ loading ? '刷新中...' : '刷新数据' }}
        </button>
        <router-link to="/scan" class="btn-primary flex items-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
          </svg>
          新建扫描
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

    <!-- 统计卡片 -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard
        title="代码单元"
        :value="stats.totalUnits || 0"
        icon="code"
        color="blue"
        :trend="5"
        trend-label="较上次扫描"
      />
      <StatCard
        title="扫描任务"
        :value="scanHistory.length"
        icon="scan"
        color="purple"
        :pulse="!!appStore.currentScan"
      />
      <StatCard
        title="发现问题"
        :value="totalFindings"
        icon="warning"
        color="orange"
        :trend="criticalCount > 0 ? -12 : 8"
        trend-label="较上周"
      />
      <StatCard
        title="安全规则"
        :value="rulesCount"
        icon="shield"
        color="green"
        :progress="rulesCoverage"
        progress-label="规则覆盖率"
      />
    </div>

    <!-- 风险概览和严重性分布 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 风险评分卡片 -->
      <div class="glass-card rounded-2xl p-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
            </svg>
          </div>
          <div>
            <h2 class="text-lg font-semibold text-gray-800">安全评分</h2>
            <p class="text-sm text-gray-500">基于发现问题计算</p>
          </div>
        </div>

        <!-- 圆环进度 -->
        <div class="flex items-center justify-center mb-6">
          <div class="relative">
            <svg class="w-36 h-36 transform -rotate-90">
              <circle
                cx="72"
                cy="72"
                r="60"
                fill="none"
                stroke="rgba(0,0,0,0.05)"
                stroke-width="12"
              />
              <circle
                cx="72"
                cy="72"
                r="60"
                fill="none"
                :stroke="scoreColor"
                stroke-width="12"
                stroke-linecap="round"
                :stroke-dasharray="`${securityScore * 3.77} 377`"
                class="transition-all duration-1000"
              />
            </svg>
            <div class="absolute inset-0 flex flex-col items-center justify-center">
              <span class="text-4xl font-bold" :class="scoreTextClass">{{ securityScore }}</span>
              <span class="text-sm text-gray-500">/ 100</span>
            </div>
          </div>
        </div>

        <div class="text-center">
          <span
            class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium"
            :class="scoreTagClass"
          >
            {{ scoreLabel }}
          </span>
        </div>
      </div>

      <!-- 严重性分布 -->
      <div class="glass-card rounded-2xl p-6 lg:col-span-2">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-lg font-semibold text-gray-800">问题严重性分布</h2>
              <p class="text-sm text-gray-500">按风险等级分类</p>
            </div>
          </div>
          <router-link to="/results" class="text-sm text-blue-600 hover:text-blue-700 font-medium">
            查看详情 →
          </router-link>
        </div>

        <div class="grid grid-cols-4 gap-4 mb-6">
          <div
            v-for="item in severityStats"
            :key="item.level"
            class="text-center p-4 rounded-xl transition-all cursor-pointer"
            :class="item.bgClass"
            @click="filterBySeverity(item.level)"
          >
            <div class="text-2xl font-bold mb-1" :class="item.textClass">{{ item.count }}</div>
            <div class="text-xs text-gray-600">{{ item.label }}</div>
          </div>
        </div>

        <!-- 横向条形图 -->
        <div class="space-y-3">
          <div v-for="item in severityStats" :key="item.level" class="flex items-center gap-3">
            <div class="w-16 text-xs font-medium text-gray-600">{{ item.label }}</div>
            <div class="flex-1 h-3 bg-gray-100 rounded-full overflow-hidden">
              <div
                class="h-full rounded-full transition-all duration-700"
                :class="item.barClass"
                :style="{ width: `${item.percentage}%` }"
              ></div>
            </div>
            <div class="w-10 text-right text-xs text-gray-500">{{ item.percentage }}%</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 语言分布和最近扫描 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- 语言分布 -->
      <div class="glass-card rounded-2xl p-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
          </div>
          <div>
            <h2 class="text-lg font-semibold text-gray-800">语言分布</h2>
            <p class="text-sm text-gray-500">已索引的代码语言</p>
          </div>
        </div>

        <div class="space-y-4">
          <div
            v-for="(count, lang) in stats.languages"
            :key="lang"
            class="flex items-center gap-4"
          >
            <div class="w-24 flex items-center gap-2">
              <div class="w-3 h-3 rounded-full" :class="getLangDotColor(lang)"></div>
              <span class="text-sm font-medium text-gray-700 capitalize">{{ lang }}</span>
            </div>
            <div class="flex-1 h-2.5 bg-gray-100 rounded-full overflow-hidden">
              <div
                class="h-full rounded-full transition-all duration-700"
                :class="getLangBarColor(lang)"
                :style="{ width: `${getPercentage(count)}%` }"
              ></div>
            </div>
            <div class="w-20 text-right">
              <span class="text-sm font-medium text-gray-700">{{ count }}</span>
              <span class="text-xs text-gray-400 ml-1">{{ getPercentage(count) }}%</span>
            </div>
          </div>
          <div v-if="Object.keys(stats.languages || {}).length === 0" class="text-center py-8 text-gray-500">
            <svg class="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
            暂无索引数据，请先扫描项目
          </div>
        </div>
      </div>

      <!-- 最近扫描 -->
      <div class="glass-card rounded-2xl p-6">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center">
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-lg font-semibold text-gray-800">最近扫描</h2>
              <p class="text-sm text-gray-500">最近的扫描记录</p>
            </div>
          </div>
          <router-link to="/results" class="text-sm text-blue-600 hover:text-blue-700 font-medium">
            查看全部 →
          </router-link>
        </div>

        <div class="space-y-3">
          <div
            v-for="scan in recentScans"
            :key="scan.scan_id"
            class="flex items-center justify-between p-4 rounded-xl bg-white/30 hover:bg-white/50 transition cursor-pointer group"
            @click="viewScan(scan.scan_id)"
          >
            <div class="flex items-center gap-3 min-w-0">
              <div class="relative">
                <div
                  class="w-10 h-10 rounded-xl flex items-center justify-center"
                  :class="getStatusBgColor(scan.status)"
                >
                  <svg v-if="scan.status === 'completed'" class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                  </svg>
                  <svg v-else-if="scan.status === 'analyzing' || scan.status === 'indexing'" class="w-5 h-5 text-blue-600 spinner" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                  <svg v-else-if="scan.status === 'failed'" class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                  <svg v-else class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                </div>
              </div>
              <div class="min-w-0">
                <div class="text-sm font-medium text-gray-800 truncate max-w-[200px]">
                  {{ getFileName(scan.target_path) }}
                </div>
                <div class="text-xs text-gray-500 flex items-center gap-2">
                  <span>{{ formatDate(scan.started_at) }}</span>
                  <span class="w-1 h-1 rounded-full bg-gray-300"></span>
                  <span :class="getStatusTextColor(scan.status)">{{ getStatusLabel(scan.status) }}</span>
                </div>
              </div>
            </div>
            <div class="flex items-center gap-3">
              <div class="text-right">
                <div class="text-sm font-medium text-gray-700">
                  {{ scan.findings_count + scan.vuln_count }}
                </div>
                <div class="text-xs text-gray-500">问题</div>
              </div>
              <svg class="w-5 h-5 text-gray-400 group-hover:text-gray-600 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
              </svg>
            </div>
          </div>

          <div v-if="scanHistory.length === 0" class="text-center py-8 text-gray-500">
            <svg class="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            暂无扫描记录
          </div>
        </div>
      </div>
    </div>

    <!-- 快速操作 -->
    <div class="glass-card rounded-2xl p-6">
      <div class="flex items-center gap-3 mb-6">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-yellow-500 to-orange-500 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div>
          <h2 class="text-lg font-semibold text-gray-800">快速操作</h2>
          <p class="text-sm text-gray-500">常用功能入口</p>
        </div>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
        <!-- 索引项目 -->
        <button @click="showIndexDialog = true" class="action-card group">
          <div class="action-icon bg-gradient-to-br from-indigo-500 to-violet-600 group-hover:scale-110">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
            </svg>
          </div>
          <span class="font-medium text-gray-800">索引项目</span>
          <span class="text-xs text-gray-500 mt-1">建立代码索引</span>
        </button>

        <router-link to="/scan" class="action-card group">
          <div class="action-icon bg-gradient-to-br from-blue-500 to-blue-600 group-hover:scale-110">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
          </div>
          <span class="font-medium text-gray-800">新建扫描</span>
          <span class="text-xs text-gray-500 mt-1">扫描项目代码</span>
        </router-link>

        <router-link to="/callgraph" class="action-card group">
          <div class="action-icon bg-gradient-to-br from-purple-500 to-pink-600 group-hover:scale-110">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
            </svg>
          </div>
          <span class="font-medium text-gray-800">调用链分析</span>
          <span class="text-xs text-gray-500 mt-1">分析函数调用</span>
        </router-link>

        <router-link to="/search" class="action-card group">
          <div class="action-icon bg-gradient-to-br from-green-500 to-emerald-600 group-hover:scale-110">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
          </div>
          <span class="font-medium text-gray-800">代码搜索</span>
          <span class="text-xs text-gray-500 mt-1">语义搜索代码</span>
        </router-link>

        <router-link to="/rules" class="action-card group">
          <div class="action-icon bg-gradient-to-br from-orange-500 to-red-500 group-hover:scale-110">
            <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
            </svg>
          </div>
          <span class="font-medium text-gray-800">安全规则</span>
          <span class="text-xs text-gray-500 mt-1">查看检测规则</span>
        </router-link>
      </div>
    </div>

    <!-- 索引项目对话框 -->
    <div v-if="showIndexDialog" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="showIndexDialog = false">
      <div class="glass-card rounded-2xl p-6 w-full max-w-md mx-4">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-800">索引项目</h3>
            <p class="text-sm text-gray-500">为项目代码建立向量索引</p>
          </div>
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">项目路径</label>
            <input
              v-model="indexPath"
              type="text"
              placeholder="输入项目目录路径..."
              class="w-full px-4 py-2.5 rounded-xl border border-gray-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 outline-none transition"
            />
          </div>

          <div class="flex items-center gap-2">
            <input
              v-model="clearExisting"
              type="checkbox"
              id="clearExisting"
              class="w-4 h-4 text-indigo-600 rounded border-gray-300 focus:ring-indigo-500"
            />
            <label for="clearExisting" class="text-sm text-gray-600">清空现有索引</label>
          </div>
        </div>

        <div class="flex justify-end gap-3 mt-6">
          <button
            @click="showIndexDialog = false"
            class="px-4 py-2 rounded-xl text-gray-600 hover:bg-gray-100 transition"
          >
            取消
          </button>
          <button
            @click="startIndex"
            :disabled="!indexPath || indexing"
            class="px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-500 to-violet-600 text-white font-medium hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {{ indexing ? '索引中...' : '开始索引' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAppStore } from '../stores/app'
import StatCard from '../components/StatCard.vue'
import IndexProgressBar from '../components/IndexProgressBar.vue'

const router = useRouter()
const appStore = useAppStore()

const loading = ref(false)
const stats = computed(() => appStore.stats)
const scanHistory = computed(() => appStore.scanHistory)
const rulesCount = ref(0)
const rulesCoverage = ref(78)

// 索引对话框状态
const showIndexDialog = ref(false)
const indexPath = ref('')
const clearExisting = ref(false)
const indexing = ref(false)

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
  return scanHistory.value.reduce((sum, s) => sum + s.findings_count + s.vuln_count, 0)
})

const criticalCount = computed(() => {
  return scanHistory.value.reduce((sum, s) => sum + (s.critical_count || 0), 0)
})

// 安全评分计算
const securityScore = computed(() => {
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
  const low = totalFindings.value - critical - high - medium
  const total = totalFindings.value || 1

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
      count: Math.max(0, low),
      percentage: Math.round((Math.max(0, low) / total) * 100),
      bgClass: 'bg-blue-50 hover:bg-blue-100',
      textClass: 'text-blue-600',
      barClass: 'bg-gradient-to-r from-blue-500 to-blue-400',
    },
  ]
})

const getPercentage = (count) => {
  const total = stats.value.totalUnits || 1
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
  router.push(`/results/${scanId}`)
}

const filterBySeverity = (level) => {
  router.push(`/results?severity=${level}`)
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
</script>

<style scoped>
.action-card {
  @apply flex flex-col items-center p-5 rounded-xl bg-white/40 hover:bg-white/60 transition-all duration-300 cursor-pointer text-center;
  backdrop-filter: blur(10px);
}

.action-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
}

.action-icon {
  @apply w-14 h-14 rounded-xl flex items-center justify-center mb-3 transition-transform duration-300;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}
</style>
