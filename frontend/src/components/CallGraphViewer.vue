<template>
  <div class="call-graph-viewer">
    <!-- 头部工具栏 -->
    <div class="toolbar">
      <div class="toolbar-left">
        <div class="icon-wrapper">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div>
          <h3 class="title">调用图可视化</h3>
          <p class="subtitle">
            {{ stats.total_nodes }} 节点 · {{ stats.total_edges }} 边
            <span v-if="isLargeGraph" class="performance-hint">(大图模式)</span>
          </p>
        </div>
      </div>

      <!-- 布局和缩放控制 -->
      <div class="toolbar-right">
        <select v-model="layoutType" @change="updateLayout" class="layout-select">
          <option value="dagre">层级布局</option>
          <option value="cose">力导向</option>
          <option value="circle">环形</option>
          <option value="concentric">同心圆</option>
          <option value="grid">网格</option>
        </select>

        <div class="zoom-controls">
          <button @click="zoomIn" class="zoom-btn" title="放大">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
            </svg>
          </button>
          <span class="zoom-level">{{ Math.round(zoomLevel * 100) }}%</span>
          <button @click="zoomOut" class="zoom-btn" title="缩小">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4"/>
            </svg>
          </button>
        </div>

        <button @click="fitGraph" class="action-btn" title="适应视图">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"/>
          </svg>
        </button>

        <button @click="toggleFullscreen" class="action-btn" title="全屏">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- 图例 -->
    <div class="legend">
      <div class="legend-item">
        <span class="legend-dot entry-point"></span>
        <span>入口点 ({{ stats.entry_points || 0 }})</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot sink"></span>
        <span>触发点 ({{ stats.sinks || 0 }})</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot function"></span>
        <span>普通函数</span>
      </div>
      <div class="legend-item" v-if="selectedNode">
        <span class="legend-dot selected"></span>
        <span>已选中</span>
      </div>
    </div>

    <!-- 图容器 -->
    <div
      ref="graphContainer"
      class="graph-container"
      :class="{ 'fullscreen': isFullscreen }"
      :style="containerStyle"
    >
      <!-- 加载指示器 -->
      <div v-if="isLoading" class="loading-overlay">
        <div class="loading-spinner"></div>
        <span>正在渲染调用图...</span>
      </div>
    </div>

    <!-- 节点详情面板 -->
    <transition name="slide-up">
      <div v-if="selectedNode" class="node-detail-panel">
        <div class="panel-header">
          <div class="panel-title">
            <span class="node-type-badge" :class="selectedNode.node_type">
              {{ nodeTypeLabels[selectedNode.node_type] || '函数' }}
            </span>
            <h4>{{ selectedNode.symbol }}</h4>
          </div>
          <button @click="selectedNode = null" class="close-btn">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div class="panel-content">
          <div class="info-row">
            <svg class="info-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
            <span class="info-label">文件:</span>
            <span class="info-value file-path">{{ selectedNode.file_path }}</span>
          </div>
          <div class="info-row">
            <svg class="info-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14"/>
            </svg>
            <span class="info-label">行号:</span>
            <span class="info-value">{{ selectedNode.line_start }} - {{ selectedNode.line_end }}</span>
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="panel-actions" v-if="selectedNode.is_sink">
          <button @click="$emit('viewChains', selectedNode)" class="btn-primary">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
            </svg>
            查看调用链
          </button>
          <button @click="$emit('analyze', selectedNode)" class="btn-secondary">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
            深度分析
          </button>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import cytoscape from 'cytoscape'

const props = defineProps({
  nodes: {
    type: Array,
    default: () => []
  },
  edges: {
    type: Array,
    default: () => []
  },
  stats: {
    type: Object,
    default: () => ({ total_nodes: 0, total_edges: 0, entry_points: 0, sinks: 0 })
  },
  height: {
    type: Number,
    default: 600
  },
  highlightSink: {
    type: String,
    default: null
  }
})

const emit = defineEmits(['nodeClick', 'viewChains', 'analyze'])

// 状态
const graphContainer = ref(null)
const layoutType = ref('dagre')
const selectedNode = ref(null)
const isLoading = ref(false)
const isFullscreen = ref(false)
const zoomLevel = ref(1)

let cy = null
let layoutTimeout = null

// 性能阈值
const LARGE_GRAPH_THRESHOLD = 200
const isLargeGraph = computed(() => props.nodes.length > LARGE_GRAPH_THRESHOLD)

// 容器样式
const containerStyle = computed(() => ({
  height: isFullscreen.value ? '100vh' : `${Math.max(props.height, 500)}px`,
  minHeight: '500px'
}))

// 节点类型标签
const nodeTypeLabels = {
  entry_point: '入口点',
  sink: '触发点',
  function: '函数',
  method: '方法',
  class: '类'
}

// 优化的 Cytoscape 样式 - 更美观
const cytoscapeStyle = [
  {
    selector: 'node',
    style: {
      'background-color': '#6366f1',
      'background-opacity': 0.9,
      'label': 'data(label)',
      'font-size': '11px',
      'font-weight': '500',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': '8px',
      'width': '36px',
      'height': '36px',
      'color': '#1f2937',
      'text-wrap': 'ellipsis',
      'text-max-width': '100px',
      'border-width': '2px',
      'border-color': '#4f46e5',
      'border-opacity': 0.5,
      'shadow-blur': '10px',
      'shadow-color': 'rgba(99, 102, 241, 0.3)',
      'shadow-offset-x': '0px',
      'shadow-offset-y': '2px',
      'shadow-opacity': 1,
      'transition-property': 'background-color, border-color, width, height',
      'transition-duration': '0.2s'
    }
  },
  {
    selector: 'node[nodeType = "entry_point"]',
    style: {
      'background-color': '#10b981',
      'border-color': '#059669',
      'shape': 'round-diamond',
      'width': '42px',
      'height': '42px',
      'shadow-color': 'rgba(16, 185, 129, 0.4)'
    }
  },
  {
    selector: 'node[nodeType = "sink"]',
    style: {
      'background-color': '#ef4444',
      'border-color': '#dc2626',
      'shape': 'star',
      'width': '44px',
      'height': '44px',
      'shadow-color': 'rgba(239, 68, 68, 0.4)'
    }
  },
  {
    selector: 'node:selected',
    style: {
      'border-width': '4px',
      'border-color': '#f59e0b',
      'border-opacity': 1,
      'shadow-blur': '15px',
      'shadow-color': 'rgba(245, 158, 11, 0.5)'
    }
  },
  {
    selector: 'node.highlighted',
    style: {
      'background-color': '#f59e0b',
      'border-width': '4px',
      'border-color': '#d97706',
      'shadow-blur': '20px',
      'shadow-color': 'rgba(245, 158, 11, 0.6)'
    }
  },
  {
    selector: 'node:active',
    style: {
      'overlay-opacity': 0.1
    }
  },
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': '#94a3b8',
      'target-arrow-color': '#94a3b8',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'arrow-scale': 1,
      'opacity': 0.7,
      'transition-property': 'line-color, width, opacity',
      'transition-duration': '0.2s'
    }
  },
  {
    selector: 'edge.highlighted',
    style: {
      'line-color': '#f59e0b',
      'target-arrow-color': '#f59e0b',
      'width': 3,
      'opacity': 1
    }
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#6366f1',
      'target-arrow-color': '#6366f1',
      'width': 3,
      'opacity': 1
    }
  }
]

// 大图简化样式
const simplifiedStyle = [
  {
    selector: 'node',
    style: {
      'background-color': '#6366f1',
      'width': '20px',
      'height': '20px',
      'label': '',
      'border-width': 0
    }
  },
  {
    selector: 'node[nodeType = "entry_point"]',
    style: {
      'background-color': '#10b981',
      'width': '24px',
      'height': '24px'
    }
  },
  {
    selector: 'node[nodeType = "sink"]',
    style: {
      'background-color': '#ef4444',
      'width': '24px',
      'height': '24px'
    }
  },
  {
    selector: 'edge',
    style: {
      'width': 1,
      'line-color': '#cbd5e1',
      'target-arrow-shape': 'none',
      'curve-style': 'haystack',
      'opacity': 0.4
    }
  }
]

// 初始化图
function initGraph() {
  if (!graphContainer.value) return

  const style = isLargeGraph.value ? simplifiedStyle : cytoscapeStyle

  cy = cytoscape({
    container: graphContainer.value,
    style: style,
    elements: [],
    layout: { name: 'preset' },
    minZoom: 0.05,
    maxZoom: 4,
    wheelSensitivity: 0.2,
    boxSelectionEnabled: false,
    autounselectify: false,
    // 性能优化选项
    textureOnViewport: isLargeGraph.value,
    hideEdgesOnViewport: isLargeGraph.value,
    hideLabelsOnViewport: isLargeGraph.value,
    motionBlur: false
  })

  // 节点点击事件
  cy.on('tap', 'node', (evt) => {
    const node = evt.target
    const nodeData = node.data()
    selectedNode.value = {
      id: nodeData.id,
      symbol: nodeData.label,
      file_path: nodeData.file_path,
      line_start: nodeData.line_start,
      line_end: nodeData.line_end,
      node_type: nodeData.nodeType,
      is_entry_point: nodeData.is_entry_point,
      is_sink: nodeData.is_sink
    }
    emit('nodeClick', selectedNode.value)
  })

  // 点击空白处取消选择
  cy.on('tap', (evt) => {
    if (evt.target === cy) {
      selectedNode.value = null
    }
  })

  // 缩放监听
  cy.on('zoom', () => {
    zoomLevel.value = cy.zoom()
  })

  updateGraph()
}

// 更新图数据 - 使用批量更新优化
function updateGraph() {
  if (!cy) return

  isLoading.value = true

  // 使用 requestAnimationFrame 进行异步批量更新
  requestAnimationFrame(() => {
    const elements = []

    // 添加节点
    for (const node of props.nodes) {
      elements.push({
        data: {
          id: node.id,
          label: node.symbol || node.id,
          file_path: node.file_path,
          line_start: node.line_start,
          line_end: node.line_end,
          nodeType: node.node_type,
          is_entry_point: node.is_entry_point,
          is_sink: node.is_sink
        }
      })
    }

    // 添加边
    for (const edge of props.edges) {
      if (edge.source && edge.target) {
        elements.push({
          data: {
            id: `${edge.source}-${edge.target}`,
            source: edge.source,
            target: edge.target
          }
        })
      }
    }

    // 批量更新
    cy.batch(() => {
      cy.elements().remove()
      cy.add(elements)
    })

    // 延迟执行布局
    if (layoutTimeout) {
      clearTimeout(layoutTimeout)
    }
    layoutTimeout = setTimeout(() => {
      updateLayout()
      isLoading.value = false
    }, 100)
  })
}

// 更新布局 - 针对大图优化
function updateLayout() {
  if (!cy || cy.elements().length === 0) return

  const nodeCount = cy.nodes().length

  let layoutConfig = {
    name: layoutType.value,
    animate: nodeCount < 100,
    animationDuration: nodeCount < 50 ? 500 : 200,
    fit: true,
    padding: 50
  }

  // 针对不同布局和图规模的配置
  switch (layoutType.value) {
    case 'dagre':
      layoutConfig = {
        ...layoutConfig,
        name: 'breadthfirst',
        directed: true,
        spacingFactor: nodeCount > 100 ? 1.0 : 1.5,
        avoidOverlap: true
      }
      break
    case 'cose':
      layoutConfig = {
        ...layoutConfig,
        name: 'cose',
        idealEdgeLength: nodeCount > 100 ? 50 : 100,
        nodeOverlap: 20,
        nodeRepulsion: nodeCount > 100 ? 2000 : 4000,
        numIter: nodeCount > 200 ? 100 : 500,
        coolingFactor: 0.95
      }
      break
    case 'circle':
      layoutConfig = {
        ...layoutConfig,
        name: 'circle',
        avoidOverlap: true
      }
      break
    case 'concentric':
      layoutConfig = {
        ...layoutConfig,
        name: 'concentric',
        avoidOverlap: true,
        concentric: (node) => {
          if (node.data('is_entry_point')) return 3
          if (node.data('is_sink')) return 1
          return 2
        },
        levelWidth: () => 2
      }
      break
    case 'grid':
      layoutConfig = {
        ...layoutConfig,
        name: 'grid',
        avoidOverlap: true,
        condense: true
      }
      break
  }

  cy.layout(layoutConfig).run()
}

// 缩放控制
function zoomIn() {
  if (cy) {
    const newZoom = Math.min(cy.zoom() * 1.3, 4)
    cy.animate({ zoom: newZoom, duration: 200 })
  }
}

function zoomOut() {
  if (cy) {
    const newZoom = Math.max(cy.zoom() / 1.3, 0.05)
    cy.animate({ zoom: newZoom, duration: 200 })
  }
}

function fitGraph() {
  if (cy) {
    cy.animate({ fit: { padding: 50 }, duration: 300 })
  }
}

// 全屏切换
function toggleFullscreen() {
  isFullscreen.value = !isFullscreen.value
  nextTick(() => {
    if (cy) {
      cy.resize()
      fitGraph()
    }
  })
}

// 高亮指定节点
function highlightNode(nodeId) {
  if (!cy) return
  cy.elements().removeClass('highlighted')
  if (nodeId) {
    const node = cy.$(`#${nodeId}`)
    if (node.length) {
      node.addClass('highlighted')
      node.neighborhood().addClass('highlighted')
      cy.animate({
        center: { eles: node },
        zoom: 1.5,
        duration: 300
      })
    }
  }
}

// 监听数据变化
watch(() => [props.nodes, props.edges], () => {
  nextTick(() => updateGraph())
}, { deep: true })

watch(() => props.highlightSink, (newVal) => {
  highlightNode(newVal)
})

// 生命周期
onMounted(() => {
  nextTick(() => initGraph())
})

onUnmounted(() => {
  if (layoutTimeout) {
    clearTimeout(layoutTimeout)
  }
  if (cy) {
    cy.destroy()
    cy = null
  }
})

// 暴露方法
defineExpose({
  highlightNode,
  fitGraph,
  updateLayout
})
</script>

<style scoped>
.call-graph-viewer {
  @apply relative;
}

.toolbar {
  @apply flex items-center justify-between mb-4 p-3 bg-white/80 backdrop-blur-sm rounded-xl border border-gray-200/50 shadow-sm;
}

.toolbar-left {
  @apply flex items-center gap-3;
}

.icon-wrapper {
  @apply w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/30;
}

.title {
  @apply text-lg font-semibold text-gray-800;
}

.subtitle {
  @apply text-sm text-gray-500;
}

.performance-hint {
  @apply text-xs text-amber-600 font-medium;
}

.toolbar-right {
  @apply flex items-center gap-3;
}

.layout-select {
  @apply px-3 py-2 text-sm rounded-lg border border-gray-200 bg-white text-gray-700 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all cursor-pointer;
}

.zoom-controls {
  @apply flex items-center gap-1 bg-gray-100 rounded-lg p-1;
}

.zoom-btn {
  @apply p-1.5 rounded-md text-gray-600 hover:bg-white hover:text-indigo-600 hover:shadow-sm transition-all;
}

.zoom-level {
  @apply text-xs font-medium text-gray-500 min-w-[40px] text-center;
}

.action-btn {
  @apply p-2 rounded-lg bg-gray-100 text-gray-600 hover:bg-indigo-100 hover:text-indigo-600 transition-all;
}

.legend {
  @apply flex flex-wrap items-center gap-4 mb-4 text-sm text-gray-600;
}

.legend-item {
  @apply flex items-center gap-2;
}

.legend-dot {
  @apply w-3 h-3 rounded-full;
}

.legend-dot.entry-point {
  @apply bg-emerald-500;
}

.legend-dot.sink {
  @apply bg-red-500;
}

.legend-dot.function {
  @apply bg-indigo-500;
}

.legend-dot.selected {
  @apply bg-amber-500;
}

.graph-container {
  @apply w-full rounded-2xl overflow-hidden relative;
  background: linear-gradient(145deg, #f8fafc 0%, #e2e8f0 50%, #f1f5f9 100%);
  box-shadow:
    inset 0 2px 4px rgba(0, 0, 0, 0.05),
    0 4px 6px -1px rgba(0, 0, 0, 0.1),
    0 2px 4px -1px rgba(0, 0, 0, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.8);
}

.graph-container.fullscreen {
  @apply fixed inset-0 z-50 rounded-none;
}

.loading-overlay {
  @apply absolute inset-0 flex flex-col items-center justify-center bg-white/80 backdrop-blur-sm z-10;
}

.loading-spinner {
  @apply w-10 h-10 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin mb-3;
}

.node-detail-panel {
  @apply mt-4 p-4 bg-white/90 backdrop-blur-sm rounded-xl border border-gray-200/50 shadow-lg;
}

.panel-header {
  @apply flex items-center justify-between mb-4;
}

.panel-title {
  @apply flex items-center gap-3;
}

.panel-title h4 {
  @apply text-lg font-semibold text-gray-800;
}

.node-type-badge {
  @apply px-2.5 py-1 rounded-full text-xs font-medium;
}

.node-type-badge.entry_point {
  @apply bg-emerald-100 text-emerald-700;
}

.node-type-badge.sink {
  @apply bg-red-100 text-red-700;
}

.node-type-badge.function {
  @apply bg-indigo-100 text-indigo-700;
}

.close-btn {
  @apply p-1 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-all;
}

.panel-content {
  @apply space-y-2;
}

.info-row {
  @apply flex items-center gap-2 text-sm;
}

.info-icon {
  @apply w-4 h-4 text-gray-400;
}

.info-label {
  @apply text-gray-500 min-w-[40px];
}

.info-value {
  @apply text-gray-700;
}

.file-path {
  @apply font-mono text-xs truncate max-w-[300px];
}

.panel-actions {
  @apply flex gap-3 mt-4 pt-4 border-t border-gray-100;
}

.btn-primary {
  @apply inline-flex items-center px-4 py-2 rounded-lg bg-gradient-to-r from-indigo-500 to-indigo-600 text-white font-medium text-sm transition-all duration-200 hover:from-indigo-600 hover:to-indigo-700 hover:shadow-lg hover:shadow-indigo-500/30;
}

.btn-secondary {
  @apply inline-flex items-center px-4 py-2 rounded-lg bg-gray-100 text-gray-700 font-medium text-sm transition-all duration-200 hover:bg-gray-200;
}

/* 动画 */
.slide-up-enter-active,
.slide-up-leave-active {
  transition: all 0.3s ease-out;
}

.slide-up-enter-from,
.slide-up-leave-to {
  opacity: 0;
  transform: translateY(10px);
}
</style>
