<template>
  <div class="call-graph-viewer">
    <!-- 头部工具栏 -->
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-gray-800">调用图</h3>
          <p class="text-sm text-gray-500">{{ stats.total_nodes }} 节点 · {{ stats.total_edges }} 边</p>
        </div>
      </div>

      <!-- 布局和缩放控制 -->
      <div class="flex items-center gap-2">
        <select v-model="layoutType" @change="updateLayout" class="input-glass text-sm py-1 px-2">
          <option value="dagre">层级布局</option>
          <option value="cose">力导向</option>
          <option value="circle">环形</option>
          <option value="concentric">同心圆</option>
        </select>
        <button @click="zoomIn" class="btn-icon" title="放大">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"/>
          </svg>
        </button>
        <button @click="zoomOut" class="btn-icon" title="缩小">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM13 10H7"/>
          </svg>
        </button>
        <button @click="fitGraph" class="btn-icon" title="适应视图">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- 图例 -->
    <div class="flex items-center gap-4 mb-4 text-xs">
      <div class="flex items-center gap-1">
        <span class="w-3 h-3 rounded-full bg-green-500"></span>
        <span class="text-gray-600">入口点 ({{ stats.entry_points }})</span>
      </div>
      <div class="flex items-center gap-1">
        <span class="w-3 h-3 rounded-full bg-red-500"></span>
        <span class="text-gray-600">触发点 ({{ stats.sinks }})</span>
      </div>
      <div class="flex items-center gap-1">
        <span class="w-3 h-3 rounded-full bg-blue-500"></span>
        <span class="text-gray-600">普通函数</span>
      </div>
    </div>

    <!-- 图容器 -->
    <div
      ref="graphContainer"
      class="graph-container glass-card rounded-xl"
      :style="{ height: height + 'px' }"
    ></div>

    <!-- 节点详情面板 -->
    <div
      v-if="selectedNode"
      class="node-detail-panel glass-card rounded-lg p-4 mt-4"
    >
      <div class="flex items-center justify-between mb-3">
        <h4 class="font-semibold text-gray-800">{{ selectedNode.symbol }}</h4>
        <button @click="selectedNode = null" class="text-gray-400 hover:text-gray-600">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>

      <div class="space-y-2 text-sm">
        <div class="flex items-center gap-2">
          <span class="text-gray-500">文件:</span>
          <span class="font-mono text-gray-700 truncate">{{ selectedNode.file_path }}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-gray-500">行号:</span>
          <span class="text-gray-700">{{ selectedNode.line_start }} - {{ selectedNode.line_end }}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-gray-500">类型:</span>
          <span
            class="px-2 py-0.5 rounded-full text-xs"
            :class="nodeTypeColors[selectedNode.node_type]"
          >
            {{ nodeTypeLabels[selectedNode.node_type] }}
          </span>
        </div>
      </div>

      <!-- 操作按钮 -->
      <div class="mt-4 flex gap-2" v-if="selectedNode.is_sink">
        <button @click="$emit('viewChains', selectedNode)" class="btn-primary text-sm px-3 py-1.5">
          查看调用链
        </button>
        <button @click="$emit('analyze', selectedNode)" class="btn-secondary text-sm px-3 py-1.5">
          分析此触发点
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
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
    default: 500
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

let cy = null

// 节点类型标签和颜色
const nodeTypeLabels = {
  entry_point: '入口点',
  sink: '触发点',
  function: '函数',
  method: '方法',
  class: '类'
}

const nodeTypeColors = {
  entry_point: 'bg-green-100 text-green-700',
  sink: 'bg-red-100 text-red-700',
  function: 'bg-blue-100 text-blue-700',
  method: 'bg-purple-100 text-purple-700',
  class: 'bg-yellow-100 text-yellow-700'
}

// Cytoscape 样式
const cytoscapeStyle = [
  {
    selector: 'node',
    style: {
      'background-color': '#3B82F6',
      'label': 'data(label)',
      'font-size': '10px',
      'text-valign': 'bottom',
      'text-margin-y': '5px',
      'width': '30px',
      'height': '30px',
      'color': '#374151',
      'text-wrap': 'ellipsis',
      'text-max-width': '80px'
    }
  },
  {
    selector: 'node[nodeType = "entry_point"]',
    style: {
      'background-color': '#10B981',
      'shape': 'diamond',
      'width': '35px',
      'height': '35px'
    }
  },
  {
    selector: 'node[nodeType = "sink"]',
    style: {
      'background-color': '#EF4444',
      'shape': 'star',
      'width': '35px',
      'height': '35px'
    }
  },
  {
    selector: 'node:selected',
    style: {
      'border-width': '3px',
      'border-color': '#2563EB',
      'border-opacity': 1
    }
  },
  {
    selector: 'node.highlighted',
    style: {
      'background-color': '#F59E0B',
      'border-width': '3px',
      'border-color': '#D97706'
    }
  },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': '#9CA3AF',
      'target-arrow-color': '#9CA3AF',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'arrow-scale': 0.8
    }
  },
  {
    selector: 'edge.highlighted',
    style: {
      'line-color': '#F59E0B',
      'target-arrow-color': '#F59E0B',
      'width': 3
    }
  }
]

// 初始化图
function initGraph() {
  if (!graphContainer.value) return

  cy = cytoscape({
    container: graphContainer.value,
    style: cytoscapeStyle,
    elements: [],
    layout: { name: 'preset' },
    minZoom: 0.1,
    maxZoom: 3,
    wheelSensitivity: 0.3
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

  updateGraph()
}

// 更新图数据
function updateGraph() {
  if (!cy) return

  // 转换数据格式
  const elements = []

  // 添加节点
  for (const node of props.nodes) {
    elements.push({
      data: {
        id: node.id,
        label: node.symbol,
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
    elements.push({
      data: {
        id: `${edge.source}-${edge.target}`,
        source: edge.source,
        target: edge.target
      }
    })
  }

  cy.elements().remove()
  cy.add(elements)
  updateLayout()
}

// 更新布局
function updateLayout() {
  if (!cy) return

  let layoutConfig = {
    name: layoutType.value,
    animate: true,
    animationDuration: 500
  }

  // 针对不同布局的配置
  switch (layoutType.value) {
    case 'dagre':
      layoutConfig = {
        ...layoutConfig,
        name: 'breadthfirst',
        directed: true,
        padding: 30,
        spacingFactor: 1.5
      }
      break
    case 'cose':
      layoutConfig = {
        ...layoutConfig,
        name: 'cose',
        idealEdgeLength: 100,
        nodeOverlap: 20,
        padding: 30
      }
      break
    case 'circle':
      layoutConfig = {
        ...layoutConfig,
        name: 'circle',
        padding: 30
      }
      break
    case 'concentric':
      layoutConfig = {
        ...layoutConfig,
        name: 'concentric',
        padding: 30,
        concentric: (node) => {
          if (node.data('is_entry_point')) return 3
          if (node.data('is_sink')) return 1
          return 2
        }
      }
      break
  }

  cy.layout(layoutConfig).run()
}

// 缩放控制
function zoomIn() {
  if (cy) cy.zoom(cy.zoom() * 1.2)
}

function zoomOut() {
  if (cy) cy.zoom(cy.zoom() / 1.2)
}

function fitGraph() {
  if (cy) cy.fit(undefined, 50)
}

// 高亮指定节点
function highlightNode(nodeId) {
  if (!cy) return
  cy.elements().removeClass('highlighted')
  if (nodeId) {
    cy.$(`#${nodeId}`).addClass('highlighted')
    cy.$(`#${nodeId}`).neighborhood().addClass('highlighted')
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
  @apply p-4;
}

.graph-container {
  @apply w-full overflow-hidden;
  background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
}

.btn-icon {
  @apply p-2 rounded-lg bg-white/80 border border-gray-200 text-gray-600 hover:bg-gray-50 hover:text-gray-800 transition-colors;
}

.btn-primary {
  @apply inline-flex items-center px-4 py-2 rounded-lg bg-gradient-to-r from-blue-500 to-blue-600 text-white font-medium text-sm transition-all duration-200 hover:from-blue-600 hover:to-blue-700;
}

.btn-secondary {
  @apply inline-flex items-center px-3 py-1.5 rounded-lg bg-white/80 border border-gray-200 text-gray-700 font-medium text-sm transition-all duration-200 hover:bg-gray-50;
}

.input-glass {
  @apply rounded-lg border border-gray-200 bg-white/80 backdrop-blur-sm px-3 py-2 text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all duration-200;
}

.glass-card {
  @apply bg-white/80 backdrop-blur-sm border border-white/20 shadow-lg;
}

.node-detail-panel {
  animation: slideIn 0.2s ease-out;
}

@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateY(-10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
