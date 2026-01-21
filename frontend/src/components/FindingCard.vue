<template>
  <div class="finding-card" :class="[severityClass, { 'is-new': finding._isNew }]">
    <!-- Severity Badge -->
    <div class="severity-badge" :class="severityBadgeClass">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path v-if="finding.severity === 'critical'" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
        <path v-else-if="finding.severity === 'high'" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        <path v-else stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      <span class="text-xs font-medium uppercase">{{ finding.severity }}</span>
    </div>

    <!-- Title & Type -->
    <div class="mb-2">
      <h4 class="font-medium text-gray-800 text-sm leading-tight">{{ finding.title }}</h4>
      <span class="text-xs text-gray-500">{{ finding.vulnerability_type || finding.category }}</span>
    </div>

    <!-- File Location -->
    <div v-if="finding.file_path" class="flex items-center gap-1 text-xs text-gray-500 mb-2">
      <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>
      <span class="truncate font-mono">{{ formatPath(finding.file_path) }}</span>
      <span v-if="finding.line_number || finding.line_start" class="text-blue-500">:{{ finding.line_number || finding.line_start }}</span>
    </div>

    <!-- Description Preview -->
    <div v-if="finding.description || finding.summary" class="text-xs text-gray-600 line-clamp-2 mb-3">
      {{ finding.description || finding.summary }}
    </div>

    <!-- Code Evidence (collapsible) -->
    <div v-if="finding.code_evidence || finding.code_snippet" class="mb-3">
      <button
        @click="showEvidence = !showEvidence"
        class="text-xs text-blue-500 hover:text-blue-600 flex items-center gap-1"
      >
        <svg class="w-3 h-3 transition-transform" :class="{ 'rotate-90': showEvidence }" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd"/>
        </svg>
        {{ showEvidence ? '隐藏代码' : '查看代码证据' }}
      </button>
      <div v-if="showEvidence" class="mt-2 bg-gray-900 rounded-lg p-3 overflow-x-auto">
        <pre class="text-xs text-gray-100 font-mono whitespace-pre-wrap">{{ finding.code_evidence || finding.code_snippet }}</pre>
      </div>
    </div>

    <!-- Confidence & Validation Status -->
    <div class="flex items-center justify-between text-xs text-gray-400 pt-2 border-t border-gray-100">
      <div class="flex items-center gap-3">
        <span v-if="finding.confidence != null" class="flex items-center gap-1">
          置信度: {{ ((finding.confidence || 0) * 100).toFixed(0) }}%
        </span>
        <!-- Validation Status Badge -->
        <span v-if="validationStatus" :class="validationBadgeClass" class="px-2 py-0.5 rounded-full text-xs font-medium">
          {{ validationStatusText }}
        </span>
        <!-- Verification Stage -->
        <span v-if="verificationStage" class="text-gray-500">
          {{ verificationStageText }}
        </span>
      </div>
      <span>{{ formattedTime }}</span>
    </div>

    <!-- Triage/Verification Info (collapsible) -->
    <div v-if="hasVerificationInfo" class="mt-2">
      <button
        @click="showVerification = !showVerification"
        class="text-xs text-purple-500 hover:text-purple-600 flex items-center gap-1"
      >
        <svg class="w-3 h-3 transition-transform" :class="{ 'rotate-90': showVerification }" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd"/>
        </svg>
        {{ showVerification ? '隐藏验证详情' : '查看验证详情' }}
      </button>
      <div v-if="showVerification" class="mt-2 space-y-2">
        <!-- Triage Result -->
        <div v-if="finding.triage_result" class="bg-gray-50 rounded-lg p-2 text-xs">
          <div class="font-medium text-gray-700 mb-1">Triage 结果</div>
          <div class="text-gray-600">决策: {{ finding.triage_result.decision }}</div>
          <div v-if="finding.triage_result.reason" class="text-gray-500">{{ finding.triage_result.reason }}</div>
        </div>
        <!-- Deep Verify Result -->
        <div v-if="finding.deep_verify_result" class="bg-gray-50 rounded-lg p-2 text-xs">
          <div class="font-medium text-gray-700 mb-1">深度验证结果</div>
          <div class="text-gray-600">状态: {{ finding.deep_verify_result.status }}</div>
          <div v-if="finding.deep_verify_result.attack_scenario" class="text-gray-500 mt-1">
            攻击场景: {{ finding.deep_verify_result.attack_scenario }}
          </div>
        </div>
        <!-- Deterministic Validation -->
        <div v-if="finding._validation" class="bg-gray-50 rounded-lg p-2 text-xs">
          <div class="font-medium text-gray-700 mb-1">确定性验证</div>
          <div class="text-gray-600">状态: {{ finding._validation.status }}</div>
          <div v-if="finding._validation.issues && finding._validation.issues.length > 0" class="text-orange-500 mt-1">
            问题: {{ finding._validation.issues.map(i => i.message).join(', ') }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  finding: {
    type: Object,
    required: true,
  },
})

const showEvidence = ref(false)
const showVerification = ref(false)

const severityClass = computed(() => {
  const classes = {
    critical: 'border-l-red-500',
    high: 'border-l-orange-500',
    medium: 'border-l-yellow-500',
    low: 'border-l-blue-500',
    info: 'border-l-gray-400',
  }
  return classes[props.finding.severity] || classes.info
})

const severityBadgeClass = computed(() => {
  const classes = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
    info: 'bg-gray-100 text-gray-600',
  }
  return classes[props.finding.severity] || classes.info
})

// Validation status from P2-2 DeterministicValidator
const validationStatus = computed(() => {
  return props.finding._validation?.status || null
})

const validationBadgeClass = computed(() => {
  const status = validationStatus.value
  const classes = {
    valid: 'bg-green-100 text-green-700',
    invalid: 'bg-red-100 text-red-700',
    uncertain: 'bg-yellow-100 text-yellow-700',
    needs_review: 'bg-orange-100 text-orange-700',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
})

const validationStatusText = computed(() => {
  const status = validationStatus.value
  const texts = {
    valid: '已验证',
    invalid: '无效',
    uncertain: '不确定',
    needs_review: '需审查',
  }
  return texts[status] || status
})

// Verification stage from P2-1 MultiStageVerifier
const verificationStage = computed(() => {
  if (props.finding.deep_verify_result) return 'deep_verify'
  if (props.finding.triage_result) return 'triage'
  return null
})

const verificationStageText = computed(() => {
  const stage = verificationStage.value
  const texts = {
    triage: 'Triage',
    deep_verify: '深度验证',
  }
  return texts[stage] || ''
})

// Check if any verification info is available
const hasVerificationInfo = computed(() => {
  return props.finding.triage_result ||
         props.finding.deep_verify_result ||
         props.finding._validation
})

const formattedTime = computed(() => {
  const ts = props.finding.received_at || props.finding.created_at
  if (!ts) return ''
  const date = new Date(ts)
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
})

const formatPath = (path) => {
  if (!path) return ''
  const parts = path.replace(/\\/g, '/').split('/')
  if (parts.length > 3) {
    return '.../' + parts.slice(-2).join('/')
  }
  return path
}
</script>

<style scoped>
.finding-card {
  @apply relative rounded-xl p-4 transition-all duration-300 border-l-4;
  background: rgba(255, 255, 255, 0.75);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-top: 1px solid rgba(255, 255, 255, 0.5);
  border-right: 1px solid rgba(255, 255, 255, 0.5);
  border-bottom: 1px solid rgba(255, 255, 255, 0.5);
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.04);
}

.finding-card:hover {
  background: rgba(255, 255, 255, 0.85);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
  transform: translateX(2px);
}

.finding-card.is-new {
  animation: slide-in 0.4s ease-out, pulse-highlight 1s ease-out 0.4s;
}

@keyframes slide-in {
  0% {
    opacity: 0;
    transform: translateY(-10px);
  }
  100% {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes pulse-highlight {
  0% {
    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4);
  }
  70% {
    box-shadow: 0 0 0 8px rgba(59, 130, 246, 0);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0);
  }
}

.severity-badge {
  @apply absolute top-3 right-3 flex items-center gap-1 px-2 py-1 rounded-full;
}

.line-clamp-2 {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
</style>
