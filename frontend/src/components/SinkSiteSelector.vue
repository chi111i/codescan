<template>
  <div class="sink-site-selector">
    <!-- 头部统计 -->
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500 to-red-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-gray-800">危险函数触发点</h3>
          <p class="text-sm text-gray-500">共发现 {{ sinkSites.length }} 个触发点，已选择 {{ selectedIds.length }} 个</p>
        </div>
      </div>

      <!-- 操作按钮 -->
      <div class="flex items-center gap-2">
        <button @click="selectAll" class="btn-secondary text-sm px-3 py-1.5">
          全选
        </button>
        <button @click="selectNone" class="btn-secondary text-sm px-3 py-1.5">
          取消
        </button>
        <button @click="selectTopN" class="btn-secondary text-sm px-3 py-1.5">
          选择 Top {{ topN }}
        </button>
      </div>
    </div>

    <!-- 过滤器 -->
    <div class="flex flex-wrap gap-3 mb-4">
      <!-- 类别过滤 -->
      <div class="flex items-center gap-2">
        <span class="text-sm text-gray-600">类别:</span>
        <select v-model="filterCategory" class="input-glass text-sm py-1 px-2 min-w-[120px]">
          <option value="">全部</option>
          <option v-for="cat in categories" :key="cat" :value="cat">{{ categoryLabels[cat] || cat }}</option>
        </select>
      </div>

      <!-- 风险等级过滤 -->
      <div class="flex items-center gap-2">
        <span class="text-sm text-gray-600">风险:</span>
        <select v-model="filterRiskLevel" class="input-glass text-sm py-1 px-2 min-w-[100px]">
          <option value="">全部</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
      </div>

      <!-- 搜索 -->
      <div class="flex-1 min-w-[200px]">
        <input
          v-model="searchQuery"
          type="text"
          class="input-glass text-sm w-full"
          placeholder="搜索文件路径、函数名..."
        />
      </div>
    </div>

    <!-- 统计卡片 -->
    <div v-if="stats" class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
      <div v-for="(count, level) in stats.by_risk_level" :key="level" class="glass-card rounded-lg p-3">
        <div class="flex items-center justify-between">
          <span class="text-xs font-medium" :class="riskLevelColors[level]">
            {{ riskLevelLabels[level] }}
          </span>
          <span class="text-lg font-bold text-gray-800">{{ count }}</span>
        </div>
      </div>
    </div>

    <!-- 触发点列表 -->
    <div class="space-y-2 max-h-[500px] overflow-y-auto pr-2">
      <div
        v-for="site in filteredSites"
        :key="site.id"
        class="sink-site-item glass-card rounded-lg p-4 cursor-pointer transition-all duration-200"
        :class="{ 'ring-2 ring-blue-500 bg-blue-50/50': selectedIds.includes(site.id) }"
        @click="toggleSelect(site.id)"
      >
        <div class="flex items-start gap-3">
          <!-- 选择框 -->
          <div class="pt-1">
            <input
              type="checkbox"
              :checked="selectedIds.includes(site.id)"
              @click.stop
              @change="toggleSelect(site.id)"
              class="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
          </div>

          <!-- 内容 -->
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1">
              <!-- 风险等级标签 -->
              <span
                class="px-2 py-0.5 text-xs font-medium rounded-full"
                :class="riskLevelBadgeColors[site.risk_level]"
              >
                {{ riskLevelLabels[site.risk_level] }}
              </span>

              <!-- 类别标签 -->
              <span class="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600">
                {{ categoryLabels[site.sink_category] || site.sink_category }}
              </span>

              <!-- 函数名 -->
              <span class="font-mono text-sm font-semibold text-gray-900 truncate">
                {{ site.symbol }}
              </span>
            </div>

            <!-- 文件路径 -->
            <div class="text-xs text-gray-500 mb-2 truncate">
              {{ site.file_path }}:{{ site.line_start }}
            </div>

            <!-- 代码片段 -->
            <div class="bg-gray-900 rounded-md p-2 overflow-x-auto">
              <pre class="text-xs text-gray-300 font-mono whitespace-pre-wrap">{{ site.call_snippet }}</pre>
            </div>

            <!-- 匹配模式 -->
            <div class="mt-2 flex flex-wrap gap-1">
              <span
                v-for="pattern in site.matched_patterns.slice(0, 3)"
                :key="pattern"
                class="px-1.5 py-0.5 text-xs bg-yellow-100 text-yellow-700 rounded"
              >
                {{ pattern }}
              </span>
              <span v-if="site.matched_patterns.length > 3" class="text-xs text-gray-400">
                +{{ site.matched_patterns.length - 3 }} more
              </span>
            </div>

            <!-- 查看调用链按钮 (仅两步确认模式) -->
            <div v-if="interactionMode === 'two-step'" class="mt-3 pt-2 border-t border-gray-100">
              <button
                @click.stop="emit('view-chains', site.id)"
                class="text-xs text-purple-600 hover:text-purple-700 flex items-center gap-1 transition-colors"
              >
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
                </svg>
                查看调用链
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 空状态 -->
      <div v-if="filteredSites.length === 0" class="text-center py-8 text-gray-500">
        <svg class="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p>没有找到匹配的触发点</p>
      </div>
    </div>

    <!-- 底部操作栏 -->
    <div class="mt-4 pt-4 border-t border-gray-200 flex items-center justify-between">
      <p class="text-sm text-gray-600">
        已选择 <span class="font-semibold text-blue-600">{{ selectedIds.length }}</span> 个触发点进行分析
      </p>
      <button
        @click="$emit('analyze', selectedIds)"
        :disabled="selectedIds.length === 0 || analyzing"
        class="btn-primary px-6"
        :class="{ 'opacity-50 cursor-not-allowed': selectedIds.length === 0 || analyzing }"
      >
        <template v-if="analyzing">
          <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          分析中...
        </template>
        <template v-else>
          <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
          </svg>
          开始分析
        </template>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const props = defineProps({
  sinkSites: {
    type: Array,
    default: () => []
  },
  stats: {
    type: Object,
    default: null
  },
  analyzing: {
    type: Boolean,
    default: false
  },
  topN: {
    type: Number,
    default: 20
  },
  interactionMode: {
    type: String,
    default: 'two-step',
    validator: (v) => ['two-step', 'one-click'].includes(v)
  }
})

const emit = defineEmits(['analyze', 'update:selected', 'view-chains'])

// 状态
const selectedIds = ref([])
const filterCategory = ref('')
const filterRiskLevel = ref('')
const searchQuery = ref('')

// 解构 props 用于模板
const interactionMode = computed(() => props.interactionMode)

// 类别标签映射
const categoryLabels = {
  command_exec: '命令执行',
  code_exec: '代码执行',
  sql_injection: 'SQL注入',
  file_read: '文件读取',
  file_write: '文件写入',
  deserialization: '反序列化',
  ssrf: 'SSRF',
  xss: 'XSS',
  path_traversal: '路径穿越',
  other: '其他'
}

// 风险等级标签
const riskLevelLabels = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息'
}

// 风险等级颜色
const riskLevelColors = {
  critical: 'text-red-600',
  high: 'text-orange-600',
  medium: 'text-yellow-600',
  low: 'text-blue-600',
  info: 'text-gray-600'
}

const riskLevelBadgeColors = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-blue-100 text-blue-700',
  info: 'bg-gray-100 text-gray-700'
}

// 计算属性
const categories = computed(() => {
  const cats = new Set()
  props.sinkSites.forEach(site => cats.add(site.sink_category))
  return Array.from(cats)
})

const filteredSites = computed(() => {
  let sites = props.sinkSites

  // 按类别过滤
  if (filterCategory.value) {
    sites = sites.filter(s => s.sink_category === filterCategory.value)
  }

  // 按风险等级过滤
  if (filterRiskLevel.value) {
    sites = sites.filter(s => s.risk_level === filterRiskLevel.value)
  }

  // 按搜索词过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    sites = sites.filter(s =>
      s.file_path.toLowerCase().includes(query) ||
      s.symbol.toLowerCase().includes(query) ||
      s.call_snippet.toLowerCase().includes(query)
    )
  }

  return sites
})

// 方法
function toggleSelect(id) {
  const idx = selectedIds.value.indexOf(id)
  if (idx === -1) {
    selectedIds.value.push(id)
  } else {
    selectedIds.value.splice(idx, 1)
  }
  emit('update:selected', selectedIds.value)
}

function selectAll() {
  selectedIds.value = filteredSites.value.map(s => s.id)
  emit('update:selected', selectedIds.value)
}

function selectNone() {
  selectedIds.value = []
  emit('update:selected', selectedIds.value)
}

function selectTopN() {
  // 按风险等级排序后选择前 N 个
  const sorted = [...props.sinkSites].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    return (order[a.risk_level] || 5) - (order[b.risk_level] || 5)
  })
  selectedIds.value = sorted.slice(0, props.topN).map(s => s.id)
  emit('update:selected', selectedIds.value)
}

// 监听 sinkSites 变化，自动选择 Top N
watch(() => props.sinkSites, (newSites) => {
  if (newSites.length > 0 && selectedIds.value.length === 0) {
    selectTopN()
  }
}, { immediate: true })
</script>

<style scoped>
.sink-site-selector {
  @apply p-4;
}

.sink-site-item:hover {
  @apply shadow-md;
}

.btn-primary {
  @apply inline-flex items-center px-4 py-2 rounded-lg bg-gradient-to-r from-blue-500 to-blue-600 text-white font-medium text-sm transition-all duration-200 hover:from-blue-600 hover:to-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2;
}

.btn-secondary {
  @apply inline-flex items-center px-3 py-1.5 rounded-lg bg-white/80 border border-gray-200 text-gray-700 font-medium text-sm transition-all duration-200 hover:bg-gray-50 focus:ring-2 focus:ring-gray-300;
}

.input-glass {
  @apply w-full rounded-lg border border-gray-200 bg-white/80 backdrop-blur-sm px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all duration-200;
}

.glass-card {
  @apply bg-white/80 backdrop-blur-sm border border-white/20 shadow-lg;
}
</style>
