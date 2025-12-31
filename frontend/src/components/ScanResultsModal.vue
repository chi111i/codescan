<template>
  <Teleport to="body">
    <Transition name="modal-fade">
      <div
        v-if="visible"
        class="fixed inset-0 z-50 flex items-center justify-center p-4"
        @click.self="handleClose"
      >
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50 backdrop-blur-sm"></div>

        <!-- Modal Container -->
        <div class="modal-container relative w-full max-w-4xl max-h-[85vh] flex flex-col rounded-2xl overflow-hidden">
          <!-- Header -->
          <div class="modal-header flex items-center justify-between px-6 py-4 border-b border-white/20">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center shadow-lg shadow-violet-500/30">
                <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                </svg>
              </div>
              <div>
                <h2 class="text-lg font-bold text-gray-800">扫描结果</h2>
                <p class="text-sm text-gray-500" v-if="scanData">
                  {{ formatPath(scanData.target_path) }}
                </p>
              </div>
            </div>
            <button
              @click="handleClose"
              class="p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>

          <!-- Loading State -->
          <div v-if="loading" class="flex-1 flex items-center justify-center py-16">
            <div class="text-center">
              <div class="inline-flex items-center justify-center w-12 h-12 mb-4">
                <svg class="animate-spin w-8 h-8 text-violet-500" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                </svg>
              </div>
              <p class="text-gray-500">加载中...</p>
            </div>
          </div>

          <!-- Error State -->
          <div v-else-if="error" class="flex-1 flex items-center justify-center py-16">
            <div class="text-center">
              <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-red-100 flex items-center justify-center">
                <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
              </div>
              <p class="text-gray-700 font-medium mb-2">加载失败</p>
              <p class="text-sm text-gray-500">{{ error }}</p>
              <button @click="fetchResults" class="mt-4 btn-primary text-sm">
                重试
              </button>
            </div>
          </div>

          <!-- Results Content -->
          <div v-else class="flex-1 overflow-y-auto p-6">
            <!-- Stats Summary -->
            <div class="grid grid-cols-4 gap-4 mb-6">
              <div class="stat-card">
                <div class="stat-icon bg-gradient-to-br from-red-500 to-rose-600">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                  </svg>
                </div>
                <div>
                  <div class="stat-value text-red-600">{{ stats.critical }}</div>
                  <div class="stat-label">严重</div>
                </div>
              </div>
              <div class="stat-card">
                <div class="stat-icon bg-gradient-to-br from-orange-500 to-amber-600">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                </div>
                <div>
                  <div class="stat-value text-orange-600">{{ stats.high }}</div>
                  <div class="stat-label">高危</div>
                </div>
              </div>
              <div class="stat-card">
                <div class="stat-icon bg-gradient-to-br from-yellow-500 to-amber-500">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                </div>
                <div>
                  <div class="stat-value text-yellow-600">{{ stats.medium }}</div>
                  <div class="stat-label">中危</div>
                </div>
              </div>
              <div class="stat-card">
                <div class="stat-icon bg-gradient-to-br from-blue-500 to-cyan-600">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                </div>
                <div>
                  <div class="stat-value text-blue-600">{{ stats.low }}</div>
                  <div class="stat-label">低危</div>
                </div>
              </div>
            </div>

            <!-- Empty State -->
            <div v-if="allFindings.length === 0" class="text-center py-12">
              <div class="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-green-400 to-emerald-500 flex items-center justify-center shadow-lg shadow-green-500/30">
                <svg class="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
              </div>
              <h3 class="text-lg font-medium text-gray-800 mb-2">未发现安全问题</h3>
              <p class="text-sm text-gray-500">扫描完成，代码中未检测到安全漏洞</p>
            </div>

            <!-- Findings List -->
            <div v-else class="space-y-3">
              <h3 class="text-sm font-medium text-gray-600 mb-3">
                共发现 {{ allFindings.length }} 个问题
              </h3>
              <FindingCard
                v-for="(finding, index) in allFindings"
                :key="finding.id || index"
                :finding="finding"
              />
            </div>
          </div>

          <!-- Footer Actions -->
          <div class="modal-footer flex items-center justify-between px-6 py-4 border-t border-white/20">
            <div class="text-sm text-gray-500">
              <span v-if="scanData?.created_at">
                扫描时间: {{ formatDateTime(scanData.created_at) }}
              </span>
            </div>
            <div class="flex gap-3">
              <button @click="handleClose" class="btn-secondary">
                关闭
              </button>
              <button v-if="allFindings.length > 0" @click="exportReport" class="btn-primary">
                <svg class="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                </svg>
                导出报告
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import * as api from '../api'
import FindingCard from './FindingCard.vue'

const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
  scanId: {
    type: String,
    default: '',
  },
})

const emit = defineEmits(['update:visible', 'close'])

const loading = ref(false)
const error = ref(null)
const scanData = ref(null)

const allFindings = computed(() => {
  if (!scanData.value) return []
  const findings = scanData.value.findings || []
  const vulnFindings = scanData.value.vuln_findings || []
  return [...findings, ...vulnFindings]
})

const stats = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  allFindings.value.forEach(f => {
    const sev = (f.severity || 'info').toLowerCase()
    if (counts[sev] !== undefined) {
      counts[sev]++
    }
  })
  return counts
})

const handleClose = () => {
  emit('update:visible', false)
  emit('close')
}

const fetchResults = async () => {
  if (!props.scanId) return

  loading.value = true
  error.value = null

  try {
    const result = await api.getScanResult(props.scanId)
    if (result.success) {
      scanData.value = result.data
    } else {
      error.value = result.message || '获取结果失败'
    }
  } catch (e) {
    console.error('Failed to fetch scan results:', e)
    error.value = e.message || '网络错误'
  } finally {
    loading.value = false
  }
}

const formatPath = (path) => {
  if (!path) return ''
  const parts = path.replace(/\\/g, '/').split('/')
  if (parts.length > 4) {
    return '.../' + parts.slice(-3).join('/')
  }
  return path
}

const formatDateTime = (dateStr) => {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

const exportReport = () => {
  if (!scanData.value || allFindings.value.length === 0) return

  const report = {
    scan_id: scanData.value.scan_id,
    target_path: scanData.value.target_path,
    created_at: scanData.value.created_at,
    status: scanData.value.status,
    stats: stats.value,
    findings: allFindings.value,
  }

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `scan-report-${props.scanId}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

watch(() => props.visible, (newVal) => {
  if (newVal && props.scanId) {
    fetchResults()
  }
})

watch(() => props.scanId, (newVal) => {
  if (props.visible && newVal) {
    fetchResults()
  }
})
</script>

<style scoped>
.modal-container {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.5);
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
}

.modal-header {
  background: linear-gradient(135deg, rgba(139, 92, 246, 0.05), rgba(167, 139, 250, 0.05));
}

.modal-footer {
  background: rgba(249, 250, 251, 0.8);
}

.stat-card {
  @apply flex items-center gap-3 p-3 rounded-xl;
  background: rgba(255, 255, 255, 0.8);
  border: 1px solid rgba(229, 231, 235, 0.8);
}

.stat-icon {
  @apply w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0;
}

.stat-value {
  @apply text-xl font-bold leading-none;
}

.stat-label {
  @apply text-xs text-gray-500 mt-0.5;
}

.btn-primary {
  @apply inline-flex items-center px-4 py-2 rounded-lg text-sm font-medium text-white transition-all duration-200;
  background: linear-gradient(135deg, #8b5cf6, #7c3aed);
  box-shadow: 0 2px 8px rgba(139, 92, 246, 0.3);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4);
}

.btn-secondary {
  @apply inline-flex items-center px-4 py-2 rounded-lg text-sm font-medium text-gray-700 transition-all duration-200;
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid rgba(229, 231, 235, 0.8);
}

.btn-secondary:hover {
  background: rgba(249, 250, 251, 1);
  border-color: rgba(209, 213, 219, 1);
}

/* Modal Transition */
.modal-fade-enter-active,
.modal-fade-leave-active {
  transition: opacity 0.25s ease;
}

.modal-fade-enter-active .modal-container,
.modal-fade-leave-active .modal-container {
  transition: transform 0.25s ease, opacity 0.25s ease;
}

.modal-fade-enter-from,
.modal-fade-leave-to {
  opacity: 0;
}

.modal-fade-enter-from .modal-container,
.modal-fade-leave-to .modal-container {
  opacity: 0;
  transform: scale(0.95) translateY(-10px);
}
</style>
