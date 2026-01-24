<template>
  <div class="llm-interaction-panel glass-card rounded-2xl p-4 flex flex-col" :class="fullHeight ? 'h-full' : 'max-h-[500px]'">
    <!-- 头部 -->
    <div class="flex items-center justify-between mb-4 shrink-0">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
          </svg>
        </div>
        <div>
          <h3 class="text-sm font-semibold text-gray-800">LLM 分析过程</h3>
          <p class="text-xs text-gray-500">
            {{ interactions.length }} 条记录
            <span v-if="tokensUsed > 0" class="ml-2">· {{ formatTokens(tokensUsed) }} tokens</span>
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <!-- 过滤器 -->
        <select
          v-model="filterType"
          class="text-xs px-2 py-1 rounded-lg bg-white/50 border border-gray-200 text-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-400"
        >
          <option value="all">全部</option>
          <option value="tool_call">工具调用</option>
          <option value="thinking">LLM 思考</option>
          <option value="analysis">分析结果</option>
          <option value="finding">发现问题</option>
        </select>
        <button
          @click="$emit('clear')"
          class="text-xs text-gray-500 hover:text-gray-700 px-2 py-1"
        >
          清空
        </button>
      </div>
    </div>

    <!-- 交互列表 -->
    <div ref="scrollContainer" class="flex-1 overflow-y-auto space-y-2 dark-scroll">
      <!-- 隐藏记录提示 -->
      <div v-if="hasHiddenItems" class="text-xs text-center text-gray-400 py-2 bg-gray-50/50 rounded-lg">
        仅显示最近 {{ MAX_VISIBLE_INTERACTIONS }} 条记录，共 {{ interactions.length }} 条
      </div>
      <template v-if="filteredInteractions.length > 0">
        <div
          v-for="(interaction, index) in filteredInteractions"
          :key="interaction.id || index"
          class="interaction-item p-3 rounded-lg border-l-4 transition-all hover:shadow-sm cursor-pointer"
          :class="getInteractionClass(interaction.type)"
          @click="toggleExpand(index)"
        >
          <!-- 头部 -->
          <div class="flex items-start justify-between">
            <div class="flex items-center gap-2 min-w-0">
              <span class="text-lg shrink-0">{{ getInteractionIcon(interaction.type) }}</span>
              <div class="min-w-0">
                <span class="text-sm font-medium text-gray-800 truncate block">
                  {{ interaction.title || getDefaultTitle(interaction) }}
                </span>
                <span v-if="interaction.tool_name" class="text-xs text-gray-500">
                  {{ interaction.tool_name }}
                </span>
              </div>
            </div>
            <div class="flex items-center gap-2 text-xs text-gray-500 shrink-0">
              <span v-if="interaction.duration_ms" class="px-1.5 py-0.5 rounded bg-white/50">
                {{ formatDuration(interaction.duration_ms) }}
              </span>
              <span v-if="interaction.tokens_used" class="px-1.5 py-0.5 rounded bg-white/50">
                {{ interaction.tokens_used }} tk
              </span>
              <span class="text-gray-400">{{ formatTime(interaction.timestamp) }}</span>
              <svg
                class="w-4 h-4 text-gray-400 transition-transform"
                :class="{ 'rotate-180': expandedItems.includes(index) }"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
              </svg>
            </div>
          </div>

          <!-- 展开内容 -->
          <transition name="expand">
            <div v-if="expandedItems.includes(index)" class="mt-3 space-y-2">
              <!-- 工具输入 -->
              <div v-if="interaction.tool_input" class="p-2 rounded-lg bg-blue-50/50">
                <div class="text-xs font-medium text-blue-600 mb-1">输入参数</div>
                <pre class="text-xs text-gray-600 overflow-x-auto whitespace-pre-wrap max-h-32 overflow-y-auto">{{ formatJSON(interaction.tool_input) }}</pre>
              </div>

              <!-- 工具输出/内容 -->
              <div v-if="interaction.tool_output || interaction.content" class="p-2 rounded-lg bg-green-50/50">
                <div class="text-xs font-medium text-green-600 mb-1">
                  {{ interaction.type === 'tool_call' ? '执行结果' : '内容' }}
                </div>
                <pre class="text-xs text-gray-600 overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto">{{ formatContent(interaction.tool_output || interaction.content) }}</pre>
              </div>

              <!-- 发现详情 -->
              <div v-if="interaction.finding" class="p-2 rounded-lg bg-orange-50/50">
                <div class="flex items-center justify-between mb-2">
                  <span class="text-xs font-medium text-orange-600">发现问题</span>
                  <span
                    class="px-2 py-0.5 rounded text-xs font-medium"
                    :class="getSeverityClass(interaction.finding.severity)"
                  >
                    {{ interaction.finding.severity }}
                  </span>
                </div>
                <p class="text-sm text-gray-800 font-medium">{{ interaction.finding.title }}</p>
                <p class="text-xs text-gray-600 mt-1">{{ interaction.finding.summary }}</p>
              </div>
            </div>
          </transition>

          <!-- 简略内容（未展开时） -->
          <div v-if="!expandedItems.includes(index) && interaction.content" class="mt-2 text-xs text-gray-600 line-clamp-2">
            {{ truncateContent(interaction.content) }}
          </div>
        </div>
      </template>

      <!-- 空状态 -->
      <div v-else class="flex flex-col items-center justify-center h-full text-gray-400 py-12">
        <svg class="w-16 h-16 mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
        </svg>
        <p class="text-sm">暂无 LLM 交互记录</p>
        <p class="text-xs mt-1">开始分析后将在此显示过程</p>
      </div>
    </div>

    <!-- 流式输出区域 -->
    <div v-if="streamingContent" class="mt-4 pt-4 border-t border-gray-200/50 shrink-0">
      <div class="flex items-center gap-2 mb-2">
        <div class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
        <span class="text-xs font-medium text-blue-600">LLM 正在输出...</span>
      </div>
      <div class="p-3 rounded-lg bg-blue-50/50 max-h-32 overflow-y-auto">
        <pre class="text-xs text-gray-700 whitespace-pre-wrap">{{ streamingContent }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'

const props = defineProps({
  interactions: {
    type: Array,
    default: () => []
  },
  streamingContent: {
    type: String,
    default: ''
  },
  fullHeight: {
    type: Boolean,
    default: false
  },
  autoScroll: {
    type: Boolean,
    default: true
  }
})

defineEmits(['clear'])

// 状态
const filterType = ref('all')
const expandedItems = ref([])
const scrollContainer = ref(null)

// 常量
const MAX_VISIBLE_INTERACTIONS = 100  // 最大显示条数

// 计算属性
const filteredInteractions = computed(() => {
  if (!props.interactions || !Array.isArray(props.interactions)) return []
  let result = props.interactions
  if (filterType.value !== 'all') {
    result = result.filter(i => i && i.type === filterType.value)
  }
  // 限制显示数量，只显示最近的记录
  if (result.length > MAX_VISIBLE_INTERACTIONS) {
    result = result.slice(-MAX_VISIBLE_INTERACTIONS)
  }
  return result
})

// 是否有被隐藏的记录
const hasHiddenItems = computed(() => {
  if (!props.interactions || !Array.isArray(props.interactions)) return false
  const total = filterType.value === 'all'
    ? props.interactions.length
    : props.interactions.filter(i => i && i.type === filterType.value).length
  return total > MAX_VISIBLE_INTERACTIONS
})

const tokensUsed = computed(() => {
  if (!props.interactions || !Array.isArray(props.interactions)) return 0
  return props.interactions.reduce((sum, i) => sum + (i?.tokens_used || 0), 0)
})

// 方法
function toggleExpand(index) {
  const idx = expandedItems.value.indexOf(index)
  if (idx > -1) {
    expandedItems.value.splice(idx, 1)
  } else {
    expandedItems.value.push(index)
  }
}

function getInteractionIcon(type) {
  const icons = {
    'tool_call': '🔧',
    'thinking': '💭',
    'analysis': '🔍',
    'finding': '⚠️',
    'error': '❌',
  }
  return icons[type] || '📝'
}

function getInteractionClass(type) {
  const classes = {
    'tool_call': 'border-blue-400 bg-blue-50/50',
    'thinking': 'border-purple-400 bg-purple-50/50',
    'analysis': 'border-green-400 bg-green-50/50',
    'finding': 'border-orange-400 bg-orange-50/50',
    'error': 'border-red-400 bg-red-50/50',
  }
  return classes[type] || 'border-gray-400 bg-gray-50/50'
}

function getDefaultTitle(interaction) {
  switch (interaction.type) {
    case 'tool_call':
      return `调用工具: ${interaction.tool_name || 'unknown'}`
    case 'thinking':
      return 'LLM 思考'
    case 'analysis':
      return '分析结果'
    case 'finding':
      return interaction.finding?.title || '发现问题'
    default:
      return interaction.type
  }
}

function getSeverityClass(severity) {
  const classes = {
    'critical': 'bg-red-500 text-white',
    'high': 'bg-orange-500 text-white',
    'medium': 'bg-yellow-500 text-white',
    'low': 'bg-blue-500 text-white',
  }
  return classes[severity] || 'bg-gray-500 text-white'
}

function formatDuration(ms) {
  if (!ms) return ''
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function formatTime(timestamp) {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function formatTokens(tokens) {
  if (tokens >= 1000) {
    return `${(tokens / 1000).toFixed(1)}k`
  }
  return tokens
}

function formatJSON(obj) {
  if (!obj) return ''
  try {
    if (typeof obj === 'string') {
      obj = JSON.parse(obj)
    }
    return JSON.stringify(obj, null, 2)
  } catch {
    return String(obj)
  }
}

function formatContent(content) {
  if (!content) return ''
  if (typeof content === 'string') {
    // 如果内容过长，截断显示
    if (content.length > 1000) {
      return content.slice(0, 1000) + '\n... (内容已截断)'
    }
    return content
  }
  return formatJSON(content)
}

function truncateContent(content) {
  if (!content) return ''
  const str = typeof content === 'string' ? content : JSON.stringify(content)
  if (str.length > 150) {
    return str.slice(0, 150) + '...'
  }
  return str
}

// 自动滚动到底部
function scrollToBottom() {
  if (props.autoScroll && scrollContainer.value) {
    nextTick(() => {
      scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight
    })
  }
}

// 监听交互变化，自动滚动
watch(() => props.interactions.length, () => {
  scrollToBottom()
})

watch(() => props.streamingContent, () => {
  scrollToBottom()
})
</script>

<style scoped>
.llm-interaction-panel {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
}

.interaction-item {
  transition: all 0.2s ease;
}

.interaction-item:hover {
  transform: translateX(2px);
}

.dark-scroll::-webkit-scrollbar {
  width: 6px;
}

.dark-scroll::-webkit-scrollbar-track {
  background: transparent;
}

.dark-scroll::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.15);
  border-radius: 3px;
}

.dark-scroll::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 0, 0, 0.25);
}

.expand-enter-active,
.expand-leave-active {
  transition: all 0.2s ease;
  overflow: hidden;
}

.expand-enter-from,
.expand-leave-to {
  opacity: 0;
  max-height: 0;
}

.expand-enter-to,
.expand-leave-from {
  opacity: 1;
  max-height: 500px;
}

.line-clamp-2 {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
</style>
