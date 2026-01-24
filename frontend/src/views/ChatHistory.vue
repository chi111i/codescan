<template>
  <div class="h-[calc(100vh-3rem)] flex flex-col">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between mb-6 shrink-0">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 mb-1 flex items-center gap-3">
          <svg class="w-7 h-7 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
          </svg>
          聊天记录
        </h1>
        <p class="text-gray-500 text-sm">查看和恢复智能审计历史会话</p>
      </div>

      <div class="flex items-center gap-3">
        <!-- 搜索框 -->
        <div class="relative">
          <input
            v-model="searchQuery"
            type="text"
            class="input-glass pl-10 pr-4 py-2 w-64"
            placeholder="搜索会话..."
          />
          <svg class="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
        </div>

        <!-- 状态筛选 -->
        <select v-model="statusFilter" class="input-glass py-2 pr-8">
          <option value="">全部状态</option>
          <option value="active">活跃</option>
          <option value="completed">已完成</option>
          <option value="archived">已归档</option>
        </select>

        <!-- 刷新按钮 -->
        <button
          @click="fetchSessions"
          class="btn-secondary p-2"
          :disabled="isLoading"
        >
          <svg
            class="w-5 h-5"
            :class="{ 'animate-spin': isLoading }"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- 统计卡片 -->
    <div class="grid grid-cols-4 gap-4 mb-6 shrink-0">
      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ stats.total }}</div>
            <div class="text-xs text-gray-500">总会话数</div>
          </div>
        </div>
      </div>

      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ stats.active }}</div>
            <div class="text-xs text-gray-500">活跃会话</div>
          </div>
        </div>
      </div>

      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-purple-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ formatNumber(stats.totalMessages) }}</div>
            <div class="text-xs text-gray-500">总消息数</div>
          </div>
        </div>
      </div>

      <div class="glass-card rounded-xl p-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/>
            </svg>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-800">{{ formatNumber(stats.totalToolCalls) }}</div>
            <div class="text-xs text-gray-500">工具调用</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 会话列表 -->
    <div class="flex-1 overflow-hidden">
      <div class="glass-card rounded-2xl p-4 h-full flex flex-col">
        <!-- 加载状态：仅在首次加载（无数据时）显示全屏加载 -->
        <div v-if="isLoading && sessions.length === 0" class="flex-1 flex items-center justify-center">
          <div class="text-center">
            <svg class="w-12 h-12 mx-auto mb-4 text-violet-500 spinner" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <p class="text-gray-500">加载中...</p>
          </div>
        </div>

        <!-- 空状态 -->
        <div v-else-if="!isLoading && filteredSessions.length === 0" class="flex-1 flex items-center justify-center">
          <div class="text-center">
            <svg class="w-20 h-20 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
            </svg>
            <p class="text-lg font-medium text-gray-500 mb-2">暂无聊天记录</p>
            <p class="text-sm text-gray-400 mb-4">开始一个新的智能审计会话</p>
            <router-link to="/audit" class="btn-primary inline-flex items-center gap-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
              </svg>
              开始智能审计
            </router-link>
          </div>
        </div>

        <!-- 会话列表 -->
        <div v-else class="flex-1 overflow-y-auto space-y-3 dark-scroll">
          <div
            v-for="session in filteredSessions"
            :key="session.session_id"
            class="session-card p-4 rounded-xl cursor-pointer transition-all duration-200"
            @click="viewSession(session)"
          >
            <div class="flex items-start justify-between">
              <div class="flex-1 min-w-0">
                <!-- 标题和状态 -->
                <div class="flex items-center gap-2 mb-1">
                  <h3 class="font-medium text-gray-800 truncate">
                    {{ session.title || '未命名会话' }}
                  </h3>
                  <span
                    class="px-2 py-0.5 rounded-full text-xs shrink-0"
                    :class="getStatusBadgeClass(session.status, session.is_active)"
                  >
                    {{ getStatusText(session.status, session.is_active) }}
                  </span>
                </div>

                <!-- 目标路径 -->
                <p class="text-sm text-gray-500 truncate mb-2">
                  <svg class="w-4 h-4 inline-block mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                  </svg>
                  {{ session.target_path || '未指定路径' }}
                </p>

                <!-- 统计信息 -->
                <div class="flex items-center gap-4 text-xs text-gray-400">
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
                    </svg>
                    {{ session.messages_count || 0 }} 条消息
                  </span>
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/>
                    </svg>
                    {{ session.tool_calls_count || 0 }} 次工具调用
                  </span>
                  <span class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    {{ formatDate(session.last_message_at || session.updated_at) }}
                  </span>
                </div>
              </div>

              <!-- 操作按钮 -->
              <div class="flex items-center gap-2 ml-4">
                <button
                  @click.stop="continueSession(session)"
                  class="btn-primary text-sm px-3 py-1.5"
                  :disabled="isRestoring === session.session_id"
                >
                  <span v-if="isRestoring === session.session_id" class="flex items-center gap-1">
                    <svg class="w-4 h-4 spinner" fill="none" viewBox="0 0 24 24">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    恢复中
                  </span>
                  <span v-else class="flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    继续
                  </span>
                </button>
                <button
                  @click.stop="deleteSession(session)"
                  class="btn-secondary text-red-500 hover:bg-red-50 p-1.5"
                  title="删除会话"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- 分页 -->
        <div v-if="totalPages > 1" class="mt-4 flex items-center justify-center gap-2 shrink-0">
          <button
            @click="currentPage--"
            :disabled="currentPage <= 1"
            class="btn-secondary px-3 py-1.5 text-sm"
          >
            上一页
          </button>
          <span class="text-sm text-gray-500">
            第 {{ currentPage }} / {{ totalPages }} 页
          </span>
          <button
            @click="currentPage++"
            :disabled="currentPage >= totalPages"
            class="btn-secondary px-3 py-1.5 text-sm"
          >
            下一页
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
// 组件名称 - 用于 keep-alive 缓存匹配
defineOptions({ name: 'ChatHistory' })

import { ref, computed, onMounted, onActivated, watch } from 'vue'
import { useRouter } from 'vue-router'
import * as api from '../api'

const router = useRouter()

// 状态
const sessions = ref([])
const isLoading = ref(false)
const isRestoring = ref(null)
const searchQuery = ref('')
const statusFilter = ref('')
const currentPage = ref(1)
const pageSize = 20
const totalCount = ref(0)

// 请求节流控制
let lastFetchTime = 0
const FETCH_THROTTLE_MS = 2000 // 2秒内不重复请求

// 统计
const stats = computed(() => {
  const total = totalCount.value
  const active = sessions.value.filter(s => s.is_active || s.status === 'active').length
  const totalMessages = sessions.value.reduce((sum, s) => sum + (s.messages_count || 0), 0)
  const totalToolCalls = sessions.value.reduce((sum, s) => sum + (s.tool_calls_count || 0), 0)
  return { total, active, totalMessages, totalToolCalls }
})

// 过滤后的会话列表
const filteredSessions = computed(() => {
  let result = sessions.value

  // 搜索过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    result = result.filter(s =>
      (s.title && s.title.toLowerCase().includes(query)) ||
      (s.target_path && s.target_path.toLowerCase().includes(query))
    )
  }

  return result
})

// 总页数
const totalPages = computed(() => Math.ceil(totalCount.value / pageSize))

// 方法
const fetchSessions = async (force = false) => {
  // 节流：2秒内不重复请求（除非强制刷新）
  const now = Date.now()
  if (!force && now - lastFetchTime < FETCH_THROTTLE_MS && sessions.value.length > 0) {
    return
  }
  lastFetchTime = now

  isLoading.value = true
  try {
    const params = {
      limit: pageSize,
      offset: (currentPage.value - 1) * pageSize,
    }
    if (statusFilter.value) {
      params.status = statusFilter.value
    }

    const result = await api.listUnifiedSessions(params)
    if (result.success) {
      sessions.value = result.data.sessions || []
      totalCount.value = result.data.total || 0
    }
  } catch (error) {
    console.error('获取会话列表失败:', error)
  } finally {
    isLoading.value = false
  }
}

const viewSession = (session) => {
  // 跳转到详情页或直接继续
  continueSession(session)
}

const continueSession = async (session) => {
  isRestoring.value = session.session_id

  try {
    // 如果会话不在活跃状态，先恢复
    if (!session.is_active) {
      const result = await api.restoreUnifiedSession(session.session_id)
      if (!result.success) {
        throw new Error(result.message || '恢复会话失败')
      }
    }

    // 跳转到审计页面，带上会话 ID
    router.push({
      path: '/audit',
      query: { session: session.session_id }
    })
  } catch (error) {
    console.error('恢复会话失败:', error)
    alert('恢复会话失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    isRestoring.value = null
  }
}

const deleteSession = async (session) => {
  if (!confirm(`确定要删除会话 "${session.title || session.session_id}" 吗？`)) {
    return
  }

  try {
    await api.deleteUnifiedSession(session.session_id)
    sessions.value = sessions.value.filter(s => s.session_id !== session.session_id)
    totalCount.value--
  } catch (error) {
    console.error('删除会话失败:', error)
    alert('删除会话失败')
  }
}

const getStatusBadgeClass = (status, isActive) => {
  if (isActive) {
    return 'bg-green-100 text-green-700'
  }
  const classes = {
    active: 'bg-green-100 text-green-700',
    completed: 'bg-blue-100 text-blue-700',
    archived: 'bg-gray-100 text-gray-600',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
}

const getStatusText = (status, isActive) => {
  if (isActive) {
    return '活跃'
  }
  const texts = {
    active: '活跃',
    completed: '已完成',
    archived: '已归档',
  }
  return texts[status] || status
}

const formatDate = (dateStr) => {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  const now = new Date()
  const diff = now - date

  // 小于 1 小时
  if (diff < 3600000) {
    const minutes = Math.floor(diff / 60000)
    return minutes <= 0 ? '刚刚' : `${minutes} 分钟前`
  }
  // 小于 24 小时
  if (diff < 86400000) {
    const hours = Math.floor(diff / 3600000)
    return `${hours} 小时前`
  }
  // 小于 7 天
  if (diff < 604800000) {
    const days = Math.floor(diff / 86400000)
    return `${days} 天前`
  }
  // 其他
  return date.toLocaleDateString('zh-CN', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

const formatNumber = (num) => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

// 监听筛选条件变化
watch([statusFilter, currentPage], () => {
  fetchSessions(true) // 筛选变化时强制刷新
})

// 生命周期
onMounted(() => {
  fetchSessions(true) // 首次加载强制请求
})

// keep-alive 激活时重新获取数据（带节流，避免频繁切换时卡顿）
onActivated(() => {
  fetchSessions() // 使用节流，2秒内不重复请求
})
</script>

<style scoped>
.session-card {
  background: rgba(255, 255, 255, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.3);
}

.session-card:hover {
  background: rgba(255, 255, 255, 0.7);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.dark-scroll::-webkit-scrollbar {
  width: 6px;
}

.dark-scroll::-webkit-scrollbar-track {
  background: transparent;
}

.dark-scroll::-webkit-scrollbar-thumb {
  background: rgba(0, 0, 0, 0.2);
  border-radius: 3px;
}

.dark-scroll::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 0, 0, 0.3);
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
