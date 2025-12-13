<template>
  <div class="space-y-6">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2">代码属性图</h1>
        <p class="text-white/60">可视化代码结构：AST + 控制流 + 数据流</p>
      </div>
      <div class="flex items-center gap-4">
        <div class="glass-subtle px-4 py-2 rounded-lg">
          <span class="text-sm text-gray-400">已构建图:</span>
          <span class="text-lg font-bold text-white ml-2">{{ graphs.length }}</span>
        </div>
      </div>
    </div>

    <!-- 主要内容区 -->
    <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
      <!-- 左侧：代码输入和图列表 -->
      <div class="lg:col-span-1 space-y-6">
        <!-- 构建新图 -->
        <div class="glass-card p-6">
          <h2 class="text-xl font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <div class="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center">
              <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
              </svg>
            </div>
            构建代码图
          </h2>

          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">编程语言</label>
              <select v-model="newGraph.language" class="select-glass">
                <option value="python">Python</option>
                <option value="javascript">JavaScript</option>
                <option value="typescript">TypeScript</option>
                <option value="java">Java</option>
                <option value="php">PHP</option>
                <option value="go">Go</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">文件路径</label>
              <input
                v-model="newGraph.file_path"
                type="text"
                class="input-glass"
                placeholder="src/example.py"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">代码内容</label>
              <textarea
                v-model="newGraph.code"
                rows="12"
                class="input-glass font-mono text-sm"
                placeholder="粘贴代码..."
              ></textarea>
            </div>

            <button
              @click="buildGraph"
              :disabled="building || !newGraph.code"
              class="btn-primary w-full"
            >
              <svg v-if="building" class="w-5 h-5 spinner mr-2" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {{ building ? '构建中...' : '构建图' }}
            </button>
          </div>
        </div>

        <!-- 已构建的图列表 -->
        <div class="glass-card p-6">
          <h2 class="text-xl font-semibold text-gray-800 mb-4">已构建图</h2>
          <div class="space-y-3 max-h-64 overflow-y-auto">
            <div
              v-for="graph in graphs"
              :key="graph.id"
              @click="selectGraph(graph.id)"
              class="p-3 glass-subtle rounded-lg cursor-pointer hover:bg-blue-50 transition-colors"
              :class="{ 'ring-2 ring-blue-500': selectedGraphId === graph.id }"
            >
              <div class="flex items-center justify-between mb-1">
                <span class="font-medium text-gray-800">{{ graph.name || 'unnamed' }}</span>
                <span class="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">
                  {{ graph.language }}
                </span>
              </div>
              <div class="text-xs text-gray-500">
                {{ graph.node_count }} 节点 | {{ graph.edge_count }} 边 | 复杂度 {{ graph.complexity }}
              </div>
            </div>
            <div v-if="graphs.length === 0" class="text-center py-8 text-gray-400">
              暂无已构建的代码图
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧：图可视化和分析 -->
      <div class="lg:col-span-3 space-y-6">
        <!-- 图可视化 -->
        <div class="glass-card p-6" v-if="selectedGraph">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-xl font-semibold text-gray-800">{{ selectedGraph.name }}</h2>
              <p class="text-sm text-gray-500">{{ selectedGraph.file_path }}</p>
            </div>
            <div class="flex items-center gap-2">
              <button
                @click="viewMode = 'graph'"
                class="px-3 py-1.5 rounded-lg text-sm"
                :class="viewMode === 'graph' ? 'bg-blue-500 text-white' : 'glass-subtle text-gray-600'"
              >
                图视图
              </button>
              <button
                @click="viewMode = 'summary'"
                class="px-3 py-1.5 rounded-lg text-sm"
                :class="viewMode === 'summary' ? 'bg-blue-500 text-white' : 'glass-subtle text-gray-600'"
              >
                LLM 摘要
              </button>
              <button
                @click="viewMode = 'json'"
                class="px-3 py-1.5 rounded-lg text-sm"
                :class="viewMode === 'json' ? 'bg-blue-500 text-white' : 'glass-subtle text-gray-600'"
              >
                JSON
              </button>
            </div>
          </div>

          <!-- 图统计信息 -->
          <div class="grid grid-cols-4 gap-4 mb-4">
            <div class="glass-subtle rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-blue-600">{{ Object.keys(selectedGraph.nodes || {}).length }}</div>
              <div class="text-xs text-gray-500">节点数</div>
            </div>
            <div class="glass-subtle rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-green-600">{{ (selectedGraph.edges || []).length }}</div>
              <div class="text-xs text-gray-500">边数</div>
            </div>
            <div class="glass-subtle rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-orange-600">{{ selectedGraph.complexity }}</div>
              <div class="text-xs text-gray-500">圈复杂度</div>
            </div>
            <div class="glass-subtle rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-purple-600">{{ selectedGraph.depth }}</div>
              <div class="text-xs text-gray-500">嵌套深度</div>
            </div>
          </div>

          <!-- 图可视化区域 -->
          <div v-if="viewMode === 'graph'" class="bg-gray-900 rounded-lg p-4 min-h-96">
            <div ref="graphContainer" class="w-full h-96">
              <!-- SVG 图可视化 -->
              <svg width="100%" height="100%" class="graph-svg">
                <!-- 边 -->
                <g class="edges">
                  <line
                    v-for="(edge, idx) in graphEdges"
                    :key="'edge-' + idx"
                    :x1="edge.x1"
                    :y1="edge.y1"
                    :x2="edge.x2"
                    :y2="edge.y2"
                    :stroke="getEdgeColor(edge.type)"
                    stroke-width="2"
                    :stroke-dasharray="edge.type.includes('data') ? '5,5' : 'none'"
                    marker-end="url(#arrowhead)"
                  />
                </g>
                <!-- 节点 -->
                <g class="nodes">
                  <g
                    v-for="node in graphNodes"
                    :key="node.id"
                    :transform="`translate(${node.x}, ${node.y})`"
                    @click="selectNode(node)"
                    class="cursor-pointer"
                  >
                    <rect
                      :width="node.width"
                      :height="30"
                      :x="-node.width/2"
                      y="-15"
                      rx="5"
                      :fill="getNodeColor(node.type)"
                      :stroke="selectedNode?.id === node.id ? '#3b82f6' : 'transparent'"
                      stroke-width="3"
                    />
                    <text
                      text-anchor="middle"
                      dominant-baseline="middle"
                      fill="white"
                      font-size="12"
                    >
                      {{ node.label }}
                    </text>
                  </g>
                </g>
                <!-- 箭头标记 -->
                <defs>
                  <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
                  </marker>
                </defs>
              </svg>
            </div>

            <!-- 图例 -->
            <div class="flex flex-wrap gap-4 mt-4 pt-4 border-t border-gray-700">
              <div class="flex items-center gap-2">
                <div class="w-4 h-4 rounded" style="background: #22c55e"></div>
                <span class="text-xs text-gray-400">函数/方法</span>
              </div>
              <div class="flex items-center gap-2">
                <div class="w-4 h-4 rounded" style="background: #f59e0b"></div>
                <span class="text-xs text-gray-400">调用</span>
              </div>
              <div class="flex items-center gap-2">
                <div class="w-4 h-4 rounded" style="background: #a855f7"></div>
                <span class="text-xs text-gray-400">条件/循环</span>
              </div>
              <div class="flex items-center gap-2">
                <div class="w-4 h-4 rounded" style="background: #3b82f6"></div>
                <span class="text-xs text-gray-400">变量/参数</span>
              </div>
              <div class="flex items-center gap-2">
                <div class="w-4 h-4 rounded" style="background: #ef4444"></div>
                <span class="text-xs text-gray-400">返回</span>
              </div>
            </div>
          </div>

          <!-- LLM 摘要视图 -->
          <div v-else-if="viewMode === 'summary'" class="bg-gray-900 rounded-lg p-4 min-h-96">
            <pre class="text-sm text-gray-100 font-mono whitespace-pre-wrap">{{ graphSummary }}</pre>
          </div>

          <!-- JSON 视图 -->
          <div v-else class="bg-gray-900 rounded-lg p-4 min-h-96 overflow-auto">
            <pre class="text-sm text-gray-100 font-mono">{{ JSON.stringify(selectedGraph, null, 2) }}</pre>
          </div>
        </div>

        <!-- 数据流分析 -->
        <div class="glass-card p-6" v-if="selectedGraph">
          <h2 class="text-xl font-semibold text-gray-800 mb-4">数据流分析</h2>

          <div class="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">源节点 (Source)</label>
              <select v-model="dataFlowConfig.source" class="select-glass">
                <option value="">选择源节点...</option>
                <option
                  v-for="node in sourceNodes"
                  :key="node.id"
                  :value="node.id"
                >
                  {{ node.name }} ({{ node.node_type }})
                </option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">汇节点 (Sink)</label>
              <select v-model="dataFlowConfig.sink" class="select-glass">
                <option value="">选择汇节点...</option>
                <option
                  v-for="node in sinkNodes"
                  :key="node.id"
                  :value="node.id"
                >
                  {{ node.name }} ({{ node.node_type }})
                </option>
              </select>
            </div>
          </div>

          <button
            @click="analyzeDataFlow"
            :disabled="analyzingFlow || !dataFlowConfig.source || !dataFlowConfig.sink"
            class="btn-primary mb-4"
          >
            <svg v-if="analyzingFlow" class="w-5 h-5 spinner mr-2" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            {{ analyzingFlow ? '分析中...' : '分析数据流路径' }}
          </button>

          <!-- 数据流路径结果 -->
          <div v-if="dataFlowPaths.length > 0" class="space-y-3">
            <div class="text-sm text-gray-600">找到 {{ dataFlowPaths.length }} 条数据流路径</div>
            <div
              v-for="(path, idx) in dataFlowPaths"
              :key="idx"
              class="glass-subtle rounded-lg p-3"
            >
              <div class="flex items-center gap-2 flex-wrap">
                <span
                  v-for="(nodeId, nidx) in path"
                  :key="nodeId"
                  class="flex items-center"
                >
                  <span class="px-2 py-1 rounded bg-blue-100 text-blue-700 text-sm">
                    {{ getNodeName(nodeId) }}
                  </span>
                  <svg v-if="nidx < path.length - 1" class="w-4 h-4 text-gray-400 mx-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                  </svg>
                </span>
              </div>
            </div>
          </div>
          <div v-else-if="dataFlowPaths.length === 0 && dataFlowConfig.source && dataFlowConfig.sink" class="text-center py-8 text-gray-400">
            未找到数据流路径
          </div>
        </div>

        <!-- 节点详情 -->
        <div class="glass-card p-6" v-if="selectedNode">
          <h2 class="text-xl font-semibold text-gray-800 mb-4">节点详情</h2>
          <div class="grid grid-cols-2 gap-4">
            <div class="glass-subtle rounded-lg p-3">
              <div class="text-sm text-gray-500">节点 ID</div>
              <div class="font-medium text-gray-800">{{ selectedNode.id }}</div>
            </div>
            <div class="glass-subtle rounded-lg p-3">
              <div class="text-sm text-gray-500">类型</div>
              <div class="font-medium text-gray-800">{{ selectedNode.node_type }}</div>
            </div>
            <div class="glass-subtle rounded-lg p-3">
              <div class="text-sm text-gray-500">名称</div>
              <div class="font-medium text-gray-800">{{ selectedNode.name }}</div>
            </div>
            <div class="glass-subtle rounded-lg p-3">
              <div class="text-sm text-gray-500">行号</div>
              <div class="font-medium text-gray-800">{{ selectedNode.line }}</div>
            </div>
          </div>
          <div v-if="selectedNode.code" class="mt-4">
            <div class="text-sm text-gray-500 mb-2">代码</div>
            <div class="bg-gray-900 rounded-lg p-3">
              <pre class="text-sm text-gray-100 font-mono">{{ selectedNode.code }}</pre>
            </div>
          </div>
        </div>

        <!-- 未选择图时的提示 -->
        <div v-if="!selectedGraph" class="glass-card p-12 text-center">
          <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"/>
          </svg>
          <h3 class="text-xl font-semibold text-gray-700 mb-2">构建或选择代码图</h3>
          <p class="text-gray-500">从左侧输入代码构建新图，或选择已有图进行分析</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'

// API 基础URL
const API_BASE = 'http://localhost:8000/api'

// 状态
const graphs = ref([])
const selectedGraphId = ref(null)
const selectedGraph = ref(null)
const graphSummary = ref('')
const selectedNode = ref(null)
const viewMode = ref('graph')
const dataFlowPaths = ref([])

// 加载状态
const building = ref(false)
const analyzingFlow = ref(false)

// 表单数据
const newGraph = reactive({
  language: 'python',
  file_path: 'example.py',
  code: `def process_user_input(request):
    user_id = request.args.get('user_id')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = db.execute(query)
    return result

def validate_input(data):
    if not data:
        raise ValueError("Empty input")
    return data.strip()`,
})

const dataFlowConfig = reactive({
  source: '',
  sink: '',
  max_depth: 10,
})

// 计算属性
const graphNodes = computed(() => {
  if (!selectedGraph.value?.nodes) return []

  const nodes = Object.values(selectedGraph.value.nodes)
  const width = 800
  const height = 400

  // 简单的层次布局
  const levels = {}
  nodes.forEach((node, idx) => {
    const level = Math.floor(idx / 4)
    if (!levels[level]) levels[level] = []
    levels[level].push(node)
  })

  const result = []
  Object.entries(levels).forEach(([level, levelNodes]) => {
    const y = 50 + parseInt(level) * 80
    levelNodes.forEach((node, idx) => {
      const x = 100 + idx * (width / (levelNodes.length + 1))
      result.push({
        ...node,
        x,
        y,
        width: Math.max(80, node.name.length * 8 + 20),
        label: node.name.slice(0, 15),
        type: node.node_type,
      })
    })
  })

  return result
})

const graphEdges = computed(() => {
  if (!selectedGraph.value?.edges || graphNodes.value.length === 0) return []

  const nodeMap = {}
  graphNodes.value.forEach(n => { nodeMap[n.id] = n })

  return selectedGraph.value.edges
    .filter(e => nodeMap[e.source_id] && nodeMap[e.target_id])
    .map(e => ({
      x1: nodeMap[e.source_id].x,
      y1: nodeMap[e.source_id].y + 15,
      x2: nodeMap[e.target_id].x,
      y2: nodeMap[e.target_id].y - 15,
      type: e.edge_type,
    }))
})

const sourceNodes = computed(() => {
  if (!selectedGraph.value?.nodes) return []
  return Object.values(selectedGraph.value.nodes).filter(n =>
    ['parameter', 'variable', 'call'].includes(n.node_type)
  )
})

const sinkNodes = computed(() => {
  if (!selectedGraph.value?.nodes) return []
  return Object.values(selectedGraph.value.nodes).filter(n =>
    ['call', 'return', 'assignment'].includes(n.node_type)
  )
})

// 方法
const loadGraphs = async () => {
  try {
    const res = await fetch(`${API_BASE}/graph/list`)
    const data = await res.json()
    if (data.success) {
      graphs.value = data.graphs
    }
  } catch (e) {
    console.error('Failed to load graphs:', e)
  }
}

const buildGraph = async () => {
  if (!newGraph.code) return

  building.value = true
  try {
    const res = await fetch(`${API_BASE}/graph/build`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newGraph),
    })
    const data = await res.json()
    if (data.success) {
      await loadGraphs()
      selectedGraph.value = data.graph
      selectedGraphId.value = data.graph.id
      graphSummary.value = data.summary
    }
  } catch (e) {
    console.error('Failed to build graph:', e)
  } finally {
    building.value = false
  }
}

const selectGraph = async (graphId) => {
  selectedGraphId.value = graphId
  selectedNode.value = null
  dataFlowPaths.value = []

  try {
    const [graphRes, summaryRes] = await Promise.all([
      fetch(`${API_BASE}/graph/${graphId}`),
      fetch(`${API_BASE}/graph/${graphId}/summary`),
    ])

    const graphData = await graphRes.json()
    const summaryData = await summaryRes.json()

    if (graphData.success) {
      selectedGraph.value = graphData.graph
    }
    if (summaryData.success) {
      graphSummary.value = summaryData.summary
    }
  } catch (e) {
    console.error('Failed to load graph:', e)
  }
}

const selectNode = (node) => {
  selectedNode.value = selectedGraph.value?.nodes?.[node.id] || node
}

const analyzeDataFlow = async () => {
  if (!selectedGraphId.value || !dataFlowConfig.source || !dataFlowConfig.sink) return

  analyzingFlow.value = true
  try {
    const res = await fetch(`${API_BASE}/graph/${selectedGraphId.value}/data-flow`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        graph_id: selectedGraphId.value,
        source_node_id: dataFlowConfig.source,
        sink_node_id: dataFlowConfig.sink,
        max_depth: dataFlowConfig.max_depth,
      }),
    })
    const data = await res.json()
    if (data.success) {
      dataFlowPaths.value = data.paths
    }
  } catch (e) {
    console.error('Failed to analyze data flow:', e)
  } finally {
    analyzingFlow.value = false
  }
}

const getNodeName = (nodeId) => {
  const node = selectedGraph.value?.nodes?.[nodeId]
  return node?.name || nodeId
}

const getNodeColor = (type) => {
  const colors = {
    function: '#22c55e',
    method: '#22c55e',
    class: '#3b82f6',
    call: '#f59e0b',
    if: '#a855f7',
    loop: '#a855f7',
    return: '#ef4444',
    variable: '#3b82f6',
    parameter: '#06b6d4',
    assignment: '#6366f1',
  }
  return colors[type] || '#6b7280'
}

const getEdgeColor = (type) => {
  if (type.includes('data')) return '#3b82f6'
  if (type.includes('control')) return '#22c55e'
  if (type.includes('call')) return '#f59e0b'
  return '#6b7280'
}

onMounted(() => {
  loadGraphs()
})
</script>

<style scoped>
.graph-svg {
  background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
}
</style>
