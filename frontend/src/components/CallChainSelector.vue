<template>
  <div class="call-chain-selector">
    <!-- 头部 -->
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"/>
          </svg>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-gray-800">调用链选择</h3>
          <p class="text-sm text-gray-500">
            {{ sinkSymbol }} · 共 {{ chains.length }} 条调用链
          </p>
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
          Top {{ topN }}
        </button>
      </div>
    </div>

    <!-- 调用链列表 -->
    <div class="space-y-3 max-h-[400px] overflow-y-auto pr-2">
      <div
        v-for="chain in sortedChains"
        :key="chain.id"
        class="chain-item glass-card rounded-lg p-4 cursor-pointer transition-all duration-200"
        :class="{ 'ring-2 ring-blue-500 bg-blue-50/50': selectedIds.includes(chain.id) }"
        @click="toggleSelect(chain.id)"
      >
        <div class="flex items-start gap-3">
          <!-- 选择框 -->
          <div class="pt-1">
            <input
              type="checkbox"
              :checked="selectedIds.includes(chain.id)"
              @click.stop
              @change="toggleSelect(chain.id)"
              class="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
          </div>

          <!-- 内容 -->
          <div class="flex-1 min-w-0">
            <!-- 风险分数和深度 -->
            <div class="flex items-center gap-2 mb-2">
              <span
                class="px-2 py-0.5 text-xs font-medium rounded-full"
                :class="getRiskScoreColor(chain.risk_score)"
              >
                风险 {{ Math.round(chain.risk_score * 100) }}%
              </span>
              <span class="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600">
                深度 {{ chain.depth }}
              </span>
              <span class="text-xs text-gray-500">
                入口: <span class="font-mono">{{ chain.entry_point }}</span>
              </span>
            </div>

            <!-- 调用链路径可视化 -->
            <div class="chain-path flex flex-wrap items-center gap-1 text-xs">
              <template v-for="(symbol, idx) in chain.path" :key="idx">
                <span
                  class="chain-node px-2 py-0.5 rounded font-mono"
                  :class="getNodeClass(symbol, idx, chain.path)"
                >
                  {{ truncateSymbol(symbol) }}
                </span>
                <svg
                  v-if="idx < chain.path.length - 1"
                  class="w-3 h-3 text-gray-400 flex-shrink-0"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                </svg>
              </template>
            </div>
          </div>
        </div>
      </div>

      <!-- 空状态 -->
      <div v-if="chains.length === 0" class="text-center py-8 text-gray-500">
        <svg class="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p>未找到调用链</p>
      </div>
    </div>

    <!-- 底部操作栏 -->
    <div class="mt-4 pt-4 border-t border-gray-200 flex items-center justify-between">
      <p class="text-sm text-gray-600">
        已选择 <span class="font-semibold text-blue-600">{{ selectedIds.length }}</span> 条调用链
      </p>
      <div class="flex gap-2">
        <button
          @click="$emit('cancel')"
          class="btn-secondary px-4"
        >
          取消
        </button>
        <button
          @click="$emit('confirm', selectedIds)"
          :disabled="selectedIds.length === 0"
          class="btn-primary px-6"
          :class="{ 'opacity-50 cursor-not-allowed': selectedIds.length === 0 }"
        >
          <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
          </svg>
          分析选中调用链
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const props = defineProps({
  sinkId: {
    type: String,
    default: ''
  },
  sinkSymbol: {
    type: String,
    default: ''
  },
  chains: {
    type: Array,
    default: () => []
  },
  topN: {
    type: Number,
    default: 5
  }
})

const emit = defineEmits(['confirm', 'cancel', 'update:selected'])

// 状态
const selectedIds = ref([])

// 按风险分数排序（安全访问）
const sortedChains = computed(() => {
  if (!props.chains || !Array.isArray(props.chains)) return []
  return [...props.chains].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
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
  selectedIds.value = props.chains.map(c => c.id)
  emit('update:selected', selectedIds.value)
}

function selectNone() {
  selectedIds.value = []
  emit('update:selected', selectedIds.value)
}

function selectTopN() {
  selectedIds.value = sortedChains.value.slice(0, props.topN).map(c => c.id)
  emit('update:selected', selectedIds.value)
}

function getRiskScoreColor(score) {
  if (score >= 0.8) return 'bg-red-100 text-red-700'
  if (score >= 0.5) return 'bg-orange-100 text-orange-700'
  if (score >= 0.3) return 'bg-yellow-100 text-yellow-700'
  return 'bg-green-100 text-green-700'
}

function getNodeClass(symbol, idx, path) {
  if (idx === 0) {
    return 'bg-green-100 text-green-700'  // 入口点
  } else if (idx === path.length - 1) {
    return 'bg-red-100 text-red-700'  // Sink
  }
  return 'bg-gray-100 text-gray-700'  // 中间节点
}

function truncateSymbol(symbol) {
  if (!symbol || typeof symbol !== 'string') return ''
  if (symbol.length > 20) {
    return symbol.substring(0, 17) + '...'
  }
  return symbol
}

// 监听 chains 变化，自动选择 Top N
watch(() => props.chains, (newChains) => {
  if (newChains.length > 0 && selectedIds.value.length === 0) {
    selectTopN()
  }
}, { immediate: true })
</script>

<style scoped>
.call-chain-selector {
  @apply p-4;
}

.chain-item:hover {
  @apply shadow-md;
}

.chain-path {
  overflow-x: auto;
  white-space: nowrap;
  scrollbar-width: thin;
}

.chain-node {
  flex-shrink: 0;
}

.btn-primary {
  @apply inline-flex items-center px-4 py-2 rounded-lg bg-gradient-to-r from-blue-500 to-blue-600 text-white font-medium text-sm transition-all duration-200 hover:from-blue-600 hover:to-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2;
}

.btn-secondary {
  @apply inline-flex items-center px-3 py-1.5 rounded-lg bg-white/80 border border-gray-200 text-gray-700 font-medium text-sm transition-all duration-200 hover:bg-gray-50 focus:ring-2 focus:ring-gray-300;
}

.glass-card {
  @apply bg-white/80 backdrop-blur-sm border border-white/20 shadow-lg;
}
</style>
