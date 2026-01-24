<template>
  <teleport to="body">
    <transition name="fade">
      <div v-if="visible" class="modal-overlay" @click.self="close">
        <div class="modal-content max-w-6xl w-[90vw] max-h-[90vh] overflow-hidden flex flex-col">
          <!-- Header -->
          <div class="flex items-center justify-between p-6 border-b border-gray-200/50 shrink-0">
            <div class="flex items-center gap-3">
              <span :class="severityBadgeClass" class="px-3 py-1 rounded-full text-sm font-semibold uppercase">
                {{ finding?.severity }}
              </span>
              <h2 class="text-xl font-bold text-gray-800">{{ finding?.title || finding?.issue_type || '漏洞详情' }}</h2>
            </div>
            <button @click="close" class="btn-icon">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>

          <!-- Content -->
          <div v-if="finding" class="flex-1 overflow-y-auto p-6 space-y-6 dark-scroll">
            <!-- Basic Info -->
            <div class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                基本信息
              </h3>
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span class="text-gray-500">漏洞类型：</span>
                  <span class="text-gray-800 font-medium">{{ finding.vulnerability_type || finding.category || finding.issue_type || finding.type }}</span>
                </div>
                <div>
                  <span class="text-gray-500">置信度：</span>
                  <span class="text-gray-800 font-medium">{{ formatConfidence(finding.confidence) }}</span>
                </div>
                <div v-if="finding.file_path">
                  <span class="text-gray-500">文件位置：</span>
                  <span class="text-gray-800 font-mono text-xs">{{ finding.file_path }}</span>
                </div>
                <div v-if="finding.line_start || finding.line_number">
                  <span class="text-gray-500">行号：</span>
                  <span class="text-gray-800 font-mono">{{ finding.line_start || finding.line_number }} - {{ finding.line_end || finding.line_start || finding.line_number }}</span>
                </div>
                <div v-if="finding.cwe_id || (finding.cwe_ids && finding.cwe_ids.length > 0)">
                  <span class="text-gray-500">CWE：</span>
                  <template v-if="finding.cwe_ids && finding.cwe_ids.length > 0">
                    <a v-for="(cweId, idx) in finding.cwe_ids" :key="cweId"
                       :href="`https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`"
                       target="_blank"
                       class="text-blue-600 hover:underline">
                      {{ cweId }}{{ idx < finding.cwe_ids.length - 1 ? ', ' : '' }}
                    </a>
                  </template>
                  <a v-else
                     :href="`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`"
                     target="_blank"
                     class="text-blue-600 hover:underline">
                    {{ finding.cwe_id }}
                  </a>
                </div>
                <div v-if="finding.created_at">
                  <span class="text-gray-500">发现时间：</span>
                  <span class="text-gray-800">{{ formatDate(finding.created_at) }}</span>
                </div>
              </div>
            </div>

            <!-- Summary / Description -->
            <div v-if="finding.summary || finding.description" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                问题描述
              </h3>
              <p class="text-gray-700 whitespace-pre-wrap leading-relaxed">{{ finding.summary || finding.description }}</p>
            </div>

            <!-- Details -->
            <div v-if="finding.details" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                </svg>
                详细分析
              </h3>
              <p class="text-gray-700 whitespace-pre-wrap leading-relaxed">{{ finding.details }}</p>
            </div>

            <!-- Code Evidence -->
            <div v-if="finding.code_evidence || finding.code_snippet || finding.sink_call" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                </svg>
                代码证据
              </h3>
              <div class="bg-gray-900 rounded-lg p-4 overflow-x-auto">
                <pre class="text-sm text-gray-100 font-mono whitespace-pre-wrap">{{ finding.code_evidence || finding.code_snippet || finding.sink_call }}</pre>
              </div>
            </div>

            <!-- Evidence Items -->
            <div v-if="finding.evidence && finding.evidence.length > 0" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-cyan-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                </svg>
                证据链 ({{ finding.evidence.length }})
              </h3>
              <div class="space-y-3">
                <div v-for="(ev, idx) in finding.evidence" :key="idx" class="bg-white/50 rounded-lg p-3">
                  <div class="flex items-center gap-2 mb-2">
                    <span class="w-6 h-6 rounded-full bg-cyan-500 text-white text-xs flex items-center justify-center font-medium">{{ idx + 1 }}</span>
                    <span v-if="ev.file_path" class="text-xs text-gray-500 font-mono">{{ ev.file_path }}:{{ ev.line_start }}</span>
                  </div>
                  <p v-if="ev.reason || ev.description" class="text-sm text-gray-700 mb-2">{{ ev.reason || ev.description }}</p>
                  <div v-if="ev.code_snippet" class="bg-gray-900 rounded p-2">
                    <pre class="text-xs text-gray-100 font-mono whitespace-pre-wrap">{{ ev.code_snippet }}</pre>
                  </div>
                </div>
              </div>
            </div>

            <!-- Attack Scenario -->
            <div v-if="finding.attack_scenario" class="glass-subtle p-4 rounded-xl border-l-4 border-red-400">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                攻击场景
              </h3>
              <p class="text-gray-700 whitespace-pre-wrap leading-relaxed">{{ finding.attack_scenario }}</p>
            </div>

            <!-- Fix Suggestion -->
            <div v-if="finding.fix_suggestion || finding.remediation" class="glass-subtle p-4 rounded-xl border-l-4 border-green-400">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                修复建议
              </h3>
              <p class="text-gray-700 whitespace-pre-wrap leading-relaxed">{{ finding.fix_suggestion || finding.remediation }}</p>
            </div>

            <!-- Call Chain -->
            <div v-if="finding.call_chain && finding.call_chain.length > 0" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
                调用链路径
              </h3>
              <div class="space-y-2">
                <div v-for="(node, idx) in finding.call_chain" :key="idx" class="flex items-center gap-2">
                  <span class="w-6 h-6 rounded-full bg-orange-500 text-white text-xs flex items-center justify-center font-medium">{{ idx + 1 }}</span>
                  <span class="text-sm text-gray-700 font-mono">{{ node.symbol || node.name || node }}</span>
                  <span v-if="node.file_path" class="text-xs text-gray-400">{{ node.file_path }}:{{ node.line_start }}</span>
                </div>
              </div>
            </div>

            <!-- Triage / Verification Results -->
            <div v-if="finding.triage_result || finding.deep_verify_result || finding._validation" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-violet-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                </svg>
                验证信息
              </h3>
              <div class="space-y-3">
                <!-- Triage Result -->
                <div v-if="finding.triage_result" class="bg-white/50 rounded-lg p-3">
                  <div class="font-medium text-gray-700 mb-1">Triage 结果</div>
                  <div class="text-sm text-gray-600">决策: {{ finding.triage_result.decision }}</div>
                  <div v-if="finding.triage_result.reason" class="text-sm text-gray-500 mt-1">{{ finding.triage_result.reason }}</div>
                </div>
                <!-- Deep Verify Result -->
                <div v-if="finding.deep_verify_result" class="bg-white/50 rounded-lg p-3">
                  <div class="font-medium text-gray-700 mb-1">深度验证结果</div>
                  <div class="text-sm text-gray-600">状态: {{ finding.deep_verify_result.status }}</div>
                  <div v-if="finding.deep_verify_result.attack_scenario" class="text-sm text-gray-500 mt-1">
                    攻击场景: {{ finding.deep_verify_result.attack_scenario }}
                  </div>
                </div>
                <!-- Deterministic Validation -->
                <div v-if="finding._validation" class="bg-white/50 rounded-lg p-3">
                  <div class="font-medium text-gray-700 mb-1">确定性验证</div>
                  <div class="text-sm text-gray-600">状态: {{ finding._validation.status }}</div>
                  <div v-if="finding._validation.issues && finding._validation.issues.length > 0" class="text-sm text-orange-500 mt-1">
                    问题: {{ finding._validation.issues.map(i => i.message).join(', ') }}
                  </div>
                </div>
              </div>
            </div>

            <!-- Notes -->
            <div v-if="finding.notes" class="glass-subtle p-4 rounded-xl">
              <h3 class="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                </svg>
                备注
              </h3>
              <p class="text-gray-700 whitespace-pre-wrap leading-relaxed">{{ finding.notes }}</p>
            </div>
          </div>

          <!-- Footer -->
          <div class="flex items-center justify-end gap-3 p-4 border-t border-gray-200/50 shrink-0">
            <button @click="close" class="btn-secondary">
              关闭
            </button>
          </div>
        </div>
      </div>
    </transition>
  </teleport>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  visible: {
    type: Boolean,
    default: false
  },
  finding: {
    type: Object,
    default: null
  }
})

const emit = defineEmits(['close'])

const close = () => {
  emit('close')
}

const severityBadgeClass = computed(() => {
  const severity = props.finding?.severity?.toLowerCase()
  const classes = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
    info: 'bg-gray-100 text-gray-600',
  }
  return classes[severity] || classes.info
})

const formatConfidence = (confidence) => {
  if (confidence == null) return '-'
  return `${(confidence * 100).toFixed(0)}%`
}

const formatDate = (dateStr) => {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}
</script>

<style scoped>
.modal-overlay {
  @apply fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm;
}

.modal-content {
  @apply bg-white/95 backdrop-blur-xl rounded-2xl shadow-2xl;
  animation: modal-in 0.2s ease-out;
}

@keyframes modal-in {
  from {
    opacity: 0;
    transform: scale(0.95) translateY(-10px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}

.glass-subtle {
  @apply bg-white/50 border border-gray-200/50;
}

.btn-icon {
  @apply p-2 rounded-lg hover:bg-gray-100 transition-colors text-gray-500 hover:text-gray-700;
}

.btn-secondary {
  @apply px-4 py-2 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200 transition-colors font-medium;
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
