<template>
  <div class="h-[calc(100vh-3rem)] flex flex-col">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between mb-4 shrink-0">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900">交互式审计</h1>
        <p class="text-gray-500 text-sm mt-1">选择代码内容，与 LLM 对话分析，确认安全发现</p>
      </div>
      <div class="flex items-center gap-3">
        <!-- 会话状态 -->
        <div v-if="currentSession" class="flex items-center gap-2 px-4 py-2 rounded-xl" :class="sessionStatusClass">
          <div class="w-2 h-2 rounded-full" :class="sessionStatusDotClass"></div>
          <span class="text-sm font-medium">{{ sessionStatusText }}</span>
        </div>
        <!-- 操作按钮 -->
        <button
          v-if="currentSession"
          @click="deleteCurrentSession"
          class="btn-secondary text-red-500 hover:bg-red-500/10"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- 无会话时：显示创建会话界面 -->
    <div v-if="!currentSession" class="flex-1 flex items-center justify-center">
      <div class="glass-card rounded-2xl p-8 max-w-xl w-full">
        <div class="text-center mb-8">
          <div class="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center">
            <svg class="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/>
            </svg>
          </div>
          <h2 class="text-2xl font-bold text-gray-800 mb-2">创建审计会话</h2>
          <p class="text-gray-500">开始一个新的交互式代码审计会话</p>
        </div>

        <form @submit.prevent="createSession" class="space-y-6">
          <!-- 目标路径 -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">目标代码路径</label>
            <input
              v-model="newSessionConfig.targetPath"
              type="text"
              class="input-glass w-full"
              placeholder="例如: /path/to/your/project"
              required
            />
          </div>

          <!-- 语言选择 -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-3">
              <span class="flex items-center gap-2">
                <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                </svg>
                扫描语言（可选）
              </span>
            </label>
            <div class="flex flex-wrap gap-3">
              <label
                v-for="lang in availableLanguages"
                :key="lang.value"
                class="lang-chip group"
                :class="{ active: newSessionConfig.languages.includes(lang.value) }"
              >
                <input
                  type="checkbox"
                  :value="lang.value"
                  v-model="newSessionConfig.languages"
                  class="hidden"
                />
                <span class="lang-icon" :class="lang.iconClass">{{ lang.icon }}</span>
                <span>{{ lang.label }}</span>
                <svg v-if="newSessionConfig.languages.includes(lang.value)" class="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
              </label>
            </div>
          </div>

          <!-- 调用链深度 -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">最大调用链深度</label>
            <input
              v-model.number="newSessionConfig.maxChainDepth"
              type="number"
              min="1"
              max="15"
              class="input-glass w-32"
            />
            <p class="text-xs text-gray-500 mt-1">追溯调用链的最大深度，默认 5</p>
          </div>

          <!-- 提交按钮 -->
          <button
            type="submit"
            class="btn-primary w-full flex items-center justify-center gap-2"
            :disabled="isCreatingSession || !newSessionConfig.targetPath"
          >
            <svg v-if="isCreatingSession" class="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>{{ isCreatingSession ? '正在创建会话...' : '创建会话' }}</span>
          </button>
        </form>

        <!-- 已有会话列表 -->
        <div v-if="existingSessions.length > 0" class="mt-8 pt-6 border-t border-gray-200/50">
          <h3 class="text-sm font-medium text-gray-700 mb-3">已有会话</h3>
          <div class="space-y-2 max-h-48 overflow-y-auto">
            <div
              v-for="session in existingSessions"
              :key="session.session_id"
              class="flex items-center justify-between p-3 rounded-xl bg-white/30 hover:bg-white/50 cursor-pointer transition-all"
              @click="loadSession(session.session_id)"
            >
              <div>
                <div class="font-medium text-gray-800 text-sm">{{ session.target_path }}</div>
                <div class="text-xs text-gray-500">
                  {{ session.code_units_count }} 代码单元 ·
                  {{ formatDate(session.created_at) }}
                </div>
              </div>
              <div class="flex items-center gap-2">
                <span class="px-2 py-1 rounded-full text-xs" :class="getSessionBadgeClass(session.status)">
                  {{ getSessionStatusText(session.status) }}
                </span>
                <button
                  @click.stop="deleteSession(session.session_id)"
                  class="p-1 rounded hover:bg-red-100 text-gray-400 hover:text-red-500"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 有会话时：显示三栏布局 -->
    <div v-else class="flex-1 grid grid-cols-12 gap-4 min-h-0">
      <!-- 左栏：代码浏览器 -->
      <div class="col-span-3 glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden">
        <div class="flex items-center justify-between mb-4 shrink-0">
          <h3 class="font-semibold text-gray-800 flex items-center gap-2">
            <svg class="w-5 h-5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
            代码浏览器
          </h3>
          <div class="flex items-center gap-1">
            <button
              @click="activeTab = 'chains'"
              class="px-2 py-1 rounded text-xs transition-all"
              :class="activeTab === 'chains' ? 'bg-purple-500 text-white' : 'text-gray-500 hover:bg-gray-100'"
            >
              调用链
            </button>
            <button
              @click="activeTab = 'sinks'"
              class="px-2 py-1 rounded text-xs transition-all"
              :class="activeTab === 'sinks' ? 'bg-orange-500 text-white' : 'text-gray-500 hover:bg-gray-100'"
            >
              Sink点
            </button>
            <button
              @click="activeTab = 'units'"
              class="px-2 py-1 rounded text-xs transition-all"
              :class="activeTab === 'units' ? 'bg-blue-500 text-white' : 'text-gray-500 hover:bg-gray-100'"
            >
              代码单元
            </button>
          </div>
        </div>

        <!-- 搜索框 -->
        <div class="mb-3 shrink-0">
          <input
            v-model="searchQuery"
            type="text"
            class="input-glass w-full text-sm"
            placeholder="搜索..."
          />
        </div>

        <!-- 调用链列表 -->
        <div v-if="activeTab === 'chains'" class="flex-1 overflow-y-auto space-y-2 dark-scroll">
          <div
            v-for="chain in filteredChains"
            :key="chain.id"
            class="chain-item p-3 rounded-xl cursor-pointer transition-all"
            :class="{
              'selected': selectedChainIds.includes(chain.id),
              'bg-white/30 hover:bg-white/50': !selectedChainIds.includes(chain.id)
            }"
            @click="toggleChainSelection(chain.id)"
          >
            <div class="flex items-start gap-2">
              <input
                type="checkbox"
                :checked="selectedChainIds.includes(chain.id)"
                class="mt-1 rounded border-gray-300"
                @click.stop
                @change="toggleChainSelection(chain.id)"
              />
              <div class="flex-1 min-w-0">
                <div class="font-medium text-gray-800 text-sm truncate">{{ chain.sink_site.symbol }}</div>
                <div class="text-xs text-gray-500 truncate">{{ chain.sink_site.file_path }}</div>
                <div class="flex items-center gap-2 mt-1">
                  <span class="px-1.5 py-0.5 rounded text-xs" :class="getRiskBadgeClass(chain.risk_level)">
                    {{ chain.risk_level }}
                  </span>
                  <span class="text-xs text-gray-400">深度 {{ chain.chain_length }}</span>
                  <span v-if="chain.has_user_input" class="text-xs text-orange-500">有输入</span>
                </div>
              </div>
            </div>
          </div>
          <div v-if="filteredChains.length === 0" class="text-center py-8 text-gray-400 text-sm">
            暂无调用链数据
          </div>
        </div>

        <!-- Sink 点列表 -->
        <div v-if="activeTab === 'sinks'" class="flex-1 overflow-y-auto space-y-2 dark-scroll">
          <div
            v-for="sink in filteredSinks"
            :key="sink.id"
            class="p-3 rounded-xl bg-white/30 hover:bg-white/50 cursor-pointer transition-all"
            @click="viewSinkDetail(sink)"
          >
            <div class="font-medium text-gray-800 text-sm truncate">{{ sink.symbol }}</div>
            <div class="text-xs text-gray-500 truncate">{{ sink.file_path }}:{{ sink.line_start }}</div>
            <div class="flex items-center gap-2 mt-1">
              <span class="px-1.5 py-0.5 rounded text-xs bg-orange-100 text-orange-600">
                {{ sink.sink_category }}
              </span>
              <span class="px-1.5 py-0.5 rounded text-xs" :class="getRiskBadgeClass(sink.risk_level)">
                {{ sink.risk_level }}
              </span>
            </div>
          </div>
          <div v-if="filteredSinks.length === 0" class="text-center py-8 text-gray-400 text-sm">
            暂无 Sink 点数据
          </div>
        </div>

        <!-- 代码单元列表 -->
        <div v-if="activeTab === 'units'" class="flex-1 overflow-y-auto space-y-2 dark-scroll">
          <div
            v-for="unit in filteredUnits"
            :key="unit.id"
            class="unit-item p-3 rounded-xl cursor-pointer transition-all"
            :class="{
              'selected': selectedUnitIds.includes(unit.id),
              'bg-white/30 hover:bg-white/50': !selectedUnitIds.includes(unit.id)
            }"
            @click="toggleUnitSelection(unit.id)"
          >
            <div class="flex items-start gap-2">
              <input
                type="checkbox"
                :checked="selectedUnitIds.includes(unit.id)"
                class="mt-1 rounded border-gray-300"
                @click.stop
                @change="toggleUnitSelection(unit.id)"
              />
              <div class="flex-1 min-w-0">
                <div class="font-medium text-gray-800 text-sm truncate">{{ unit.symbol }}</div>
                <div class="text-xs text-gray-500 truncate">{{ unit.file_path }}:{{ unit.line_start }}</div>
                <div class="flex items-center gap-2 mt-1">
                  <span class="px-1.5 py-0.5 rounded text-xs bg-blue-100 text-blue-600">
                    {{ unit.unit_type }}
                  </span>
                  <span class="text-xs text-gray-400">{{ unit.language }}</span>
                </div>
              </div>
            </div>
          </div>
          <div v-if="filteredUnits.length === 0" class="text-center py-8 text-gray-400 text-sm">
            暂无代码单元数据
          </div>
        </div>

        <!-- 已选择提示 -->
        <div v-if="selectedChainIds.length > 0 || selectedUnitIds.length > 0" class="mt-3 pt-3 border-t border-gray-200/50 shrink-0">
          <div class="flex items-center justify-between text-sm">
            <span class="text-gray-600">
              已选择 {{ selectedChainIds.length }} 条调用链，{{ selectedUnitIds.length }} 个代码单元
            </span>
            <button @click="clearSelection" class="text-gray-400 hover:text-gray-600">
              清空
            </button>
          </div>
        </div>
      </div>

      <!-- 中栏：LLM 对话面板 -->
      <div class="col-span-5 glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden">
        <div class="flex items-center justify-between mb-4 shrink-0">
          <h3 class="font-semibold text-gray-800 flex items-center gap-2">
            <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/>
            </svg>
            LLM 分析对话
          </h3>
          <div class="flex items-center gap-2">
            <button
              @click="generateSummary"
              :disabled="isAnalyzing"
              class="px-3 py-1 rounded-lg text-xs bg-green-500/10 text-green-600 hover:bg-green-500/20 transition-all"
            >
              生成总结
            </button>
            <button
              @click="stopCurrentAnalysis"
              :disabled="!isAnalyzing"
              class="px-3 py-1 rounded-lg text-xs bg-red-500/10 text-red-600 hover:bg-red-500/20 transition-all"
            >
              停止分析
            </button>
          </div>
        </div>

        <!-- 对话历史 -->
        <div ref="chatContainer" class="flex-1 overflow-y-auto space-y-4 dark-scroll mb-4">
          <div
            v-for="(msg, index) in chatMessages"
            :key="index"
            class="chat-message"
            :class="msg.role"
          >
            <div class="message-header">
              <span class="message-role">{{ msg.role === 'user' ? '你' : 'LLM' }}</span>
              <span class="message-time">{{ formatTime(msg.timestamp) }}</span>
            </div>
            <div class="message-content" v-html="renderMarkdown(msg.content)"></div>
            <!-- 如果有发现，显示发现卡片 -->
            <div v-if="msg.findings && msg.findings.length > 0" class="mt-3 space-y-2">
              <div
                v-for="finding in msg.findings"
                :key="finding.id"
                class="finding-card p-3 rounded-lg border-l-4"
                :class="getFindingSeverityClass(finding.severity)"
              >
                <div class="flex items-start justify-between">
                  <div>
                    <div class="font-medium text-gray-800">{{ finding.title }}</div>
                    <div class="text-xs text-gray-500 mt-1">{{ finding.category }} · {{ finding.file_path }}:{{ finding.line_start }}</div>
                  </div>
                  <span class="px-2 py-1 rounded text-xs" :class="getSeverityBadgeClass(finding.severity)">
                    {{ finding.severity }}
                  </span>
                </div>
                <p class="text-sm text-gray-600 mt-2">{{ finding.summary }}</p>
                <div class="flex items-center gap-2 mt-3">
                  <button
                    @click="confirmFindingAction(finding.id)"
                    class="px-2 py-1 rounded text-xs bg-green-500 text-white hover:bg-green-600"
                  >
                    确认
                  </button>
                  <button
                    @click="rejectFindingAction(finding.id)"
                    class="px-2 py-1 rounded text-xs bg-gray-300 text-gray-700 hover:bg-gray-400"
                  >
                    拒绝
                  </button>
                  <button
                    @click="digDeeperAction(finding.id)"
                    class="px-2 py-1 rounded text-xs bg-blue-500 text-white hover:bg-blue-600"
                  >
                    深入分析
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- 分析中提示 -->
          <div v-if="isAnalyzing" class="flex items-center gap-3 p-4 rounded-xl bg-blue-50">
            <div class="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center">
              <svg class="w-5 h-5 text-white spinner" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            </div>
            <div>
              <div class="font-medium text-blue-700">LLM 正在分析...</div>
              <div class="text-sm text-blue-500">{{ currentAnalysisStep }}</div>
            </div>
          </div>

          <!-- 空状态 -->
          <div v-if="chatMessages.length === 0 && !isAnalyzing" class="flex flex-col items-center justify-center h-full text-gray-400">
            <svg class="w-16 h-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/>
            </svg>
            <p class="text-center">
              选择左侧的调用链或代码单元<br/>
              点击「开始分析」按钮开始审计
            </p>
          </div>
        </div>

        <!-- 输入区域 -->
        <div class="shrink-0 space-y-3">
          <!-- 分析按钮 -->
          <div v-if="selectedChainIds.length > 0 || selectedUnitIds.length > 0" class="flex gap-2">
            <button
              @click="analyzeSelected"
              :disabled="isAnalyzing"
              class="btn-primary flex-1 flex items-center justify-center gap-2"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
              </svg>
              开始分析选中内容
            </button>
          </div>

          <!-- 对话输入 -->
          <div class="flex gap-2">
            <input
              v-model="chatInput"
              type="text"
              class="input-glass flex-1"
              placeholder="输入问题或指令，与 LLM 对话..."
              @keyup.enter="sendChatMessage"
              :disabled="isAnalyzing"
            />
            <button
              @click="sendChatMessage"
              :disabled="!chatInput.trim() || isAnalyzing"
              class="btn-primary px-4"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/>
              </svg>
            </button>
          </div>
        </div>
      </div>

      <!-- 右栏：发现管理 + FC 面板 -->
      <div class="col-span-4 flex flex-col gap-4 min-h-0 overflow-hidden">
        <!-- FC 进度面板（当启用时显示） -->
        <FCProgressPanel
          v-if="fcState.enabled"
          :current-sink="fcState.currentSink"
          :current-turn="fcState.currentTurn"
          :total-tool-calls="fcState.totalToolCalls"
          :tool-calls="fcState.toolCalls"
          :findings-count="fcState.findingsCount"
          :status="fcState.status"
          class="shrink-0"
        />

        <!-- 发现管理面板 -->
        <div class="glass-card rounded-2xl p-4 flex flex-col min-h-0 overflow-hidden flex-1">
        <div class="flex items-center justify-between mb-4 shrink-0">
          <h3 class="font-semibold text-gray-800 flex items-center gap-2">
            <svg class="w-5 h-5 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
            </svg>
            发现管理
          </h3>
          <div class="flex items-center gap-1">
            <button
              @click="findingTab = 'pending'"
              class="px-2 py-1 rounded text-xs transition-all"
              :class="findingTab === 'pending' ? 'bg-yellow-500 text-white' : 'text-gray-500 hover:bg-gray-100'"
            >
              待确认 ({{ pendingFindings.length }})
            </button>
            <button
              @click="findingTab = 'confirmed'"
              class="px-2 py-1 rounded text-xs transition-all"
              :class="findingTab === 'confirmed' ? 'bg-green-500 text-white' : 'text-gray-500 hover:bg-gray-100'"
            >
              已确认 ({{ confirmedFindings.length }})
            </button>
            <button
              @click="findingTab = 'rejected'"
              class="px-2 py-1 rounded text-xs transition-all"
              :class="findingTab === 'rejected' ? 'bg-gray-500 text-white' : 'text-gray-500 hover:bg-gray-100'"
            >
              已拒绝 ({{ rejectedFindings.length }})
            </button>
          </div>
        </div>

        <!-- 发现列表 -->
        <div class="flex-1 overflow-y-auto space-y-3 dark-scroll">
          <template v-if="currentFindings.length > 0">
            <div
              v-for="finding in currentFindings"
              :key="finding.id"
              class="finding-detail-card p-4 rounded-xl"
              :class="getFindingCardClass(finding)"
            >
              <div class="flex items-start justify-between mb-2">
                <div class="flex-1">
                  <div class="font-semibold text-gray-800">{{ finding.title }}</div>
                  <div class="text-xs text-gray-500 mt-1">
                    {{ finding.category }} · {{ finding.file_path }}:{{ finding.line_start }}
                  </div>
                </div>
                <span class="px-2 py-1 rounded text-xs shrink-0" :class="getSeverityBadgeClass(finding.severity)">
                  {{ finding.severity }}
                </span>
              </div>

              <p class="text-sm text-gray-600 mb-3">{{ finding.summary }}</p>

              <!-- 详细信息折叠 -->
              <details class="mb-3">
                <summary class="text-xs text-blue-500 cursor-pointer hover:text-blue-600">
                  查看详情
                </summary>
                <div class="mt-2 p-3 rounded-lg bg-white/50 text-sm space-y-2">
                  <div v-if="finding.details">
                    <div class="font-medium text-gray-700 text-xs mb-1">详细分析</div>
                    <p class="text-gray-600 text-xs">{{ finding.details }}</p>
                  </div>
                  <div v-if="finding.attack_scenario">
                    <div class="font-medium text-gray-700 text-xs mb-1">攻击场景</div>
                    <p class="text-gray-600 text-xs">{{ finding.attack_scenario }}</p>
                  </div>
                  <div v-if="finding.fix_suggestion">
                    <div class="font-medium text-gray-700 text-xs mb-1">修复建议</div>
                    <p class="text-gray-600 text-xs">{{ finding.fix_suggestion }}</p>
                  </div>
                </div>
              </details>

              <!-- 操作按钮 -->
              <div v-if="finding.status === 'pending'" class="flex items-center gap-2">
                <button
                  @click="confirmFindingAction(finding.id)"
                  class="flex-1 px-3 py-1.5 rounded-lg text-xs bg-green-500 text-white hover:bg-green-600 transition-all"
                >
                  确认漏洞
                </button>
                <button
                  @click="rejectFindingAction(finding.id)"
                  class="flex-1 px-3 py-1.5 rounded-lg text-xs bg-gray-300 text-gray-700 hover:bg-gray-400 transition-all"
                >
                  误报
                </button>
                <button
                  @click="digDeeperAction(finding.id)"
                  class="px-3 py-1.5 rounded-lg text-xs bg-blue-500 text-white hover:bg-blue-600 transition-all"
                >
                  深入
                </button>
              </div>

              <!-- 已确认/已拒绝状态 -->
              <div v-else class="text-xs text-gray-500">
                <span v-if="finding.status === 'confirmed'">
                  已确认 · {{ finding.user_notes || '无备注' }}
                </span>
                <span v-else>
                  已拒绝 · {{ finding.rejected_reason || '无原因' }}
                </span>
              </div>
            </div>
          </template>

          <!-- 空状态 -->
          <div v-else class="flex flex-col items-center justify-center h-full text-gray-400">
            <svg class="w-16 h-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
            </svg>
            <p class="text-center text-sm">
              {{ findingTab === 'pending' ? '暂无待确认的发现' : findingTab === 'confirmed' ? '暂无已确认的发现' : '暂无已拒绝的发现' }}
            </p>
          </div>
        </div>

        <!-- 统计信息 -->
        <div class="mt-4 pt-4 border-t border-gray-200/50 shrink-0">
          <div class="grid grid-cols-3 gap-4 text-center">
            <div>
              <div class="text-2xl font-bold text-yellow-600">{{ pendingFindings.length }}</div>
              <div class="text-xs text-gray-500">待确认</div>
            </div>
            <div>
              <div class="text-2xl font-bold text-green-600">{{ confirmedFindings.length }}</div>
              <div class="text-xs text-gray-500">已确认</div>
            </div>
            <div>
              <div class="text-2xl font-bold text-gray-500">{{ rejectedFindings.length }}</div>
              <div class="text-xs text-gray-500">已拒绝</div>
            </div>
          </div>
        </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import * as api from '../api'
import { useAuditStore } from '../stores/auditStore'
import FCProgressPanel from '../components/FCProgressPanel.vue'

// ============ 状态 ============

// 获取 auditStore 实例
const auditStore = useAuditStore()

// Function Calling 状态
const fcState = reactive({
  enabled: false,
  status: 'idle', // idle, analyzing, completed, failed
  currentSink: '',
  currentTurn: 0,
  totalToolCalls: 0,
  toolCalls: [],
  findingsCount: 0,
})

// 重置 FC 状态
const resetFCState = () => {
  fcState.enabled = false
  fcState.status = 'idle'
  fcState.currentSink = ''
  fcState.currentTurn = 0
  fcState.totalToolCalls = 0
  fcState.toolCalls = []
  fcState.findingsCount = 0
}

// 会话管理
const currentSession = ref(null)
const existingSessions = ref([])
const isCreatingSession = ref(false)
const newSessionConfig = reactive({
  targetPath: '',
  languages: [],
  maxChainDepth: 5,
})

// 代码浏览
const activeTab = ref('chains')
const searchQuery = ref('')
const chainContexts = ref([])
const sinkSites = ref([])
const codeUnits = ref([])
const selectedChainIds = ref([])
const selectedUnitIds = ref([])

// LLM 对话
const chatMessages = ref([])
const chatInput = ref('')
const isAnalyzing = ref(false)
const currentAnalysisStep = ref('')
const chatContainer = ref(null)

// 发现管理
const findingTab = ref('pending')
const pendingFindings = ref([])
const confirmedFindings = ref([])
const rejectedFindings = ref([])

// WebSocket
let ws = null

// ============ 导入语言配置 ============
import { AVAILABLE_LANGUAGES } from '@/constants/languages'

// ============ 计算属性 ============

const availableLanguages = AVAILABLE_LANGUAGES

const sessionStatusClass = computed(() => {
  if (!currentSession.value) return ''
  const status = currentSession.value.status
  const classes = {
    ready: 'bg-green-500/20 text-green-300',
    analyzing: 'bg-blue-500/20 text-blue-300',
    paused: 'bg-yellow-500/20 text-yellow-300',
    error: 'bg-red-500/20 text-red-300',
  }
  return classes[status] || 'bg-gray-500/20 text-gray-300'
})

const sessionStatusDotClass = computed(() => {
  if (!currentSession.value) return ''
  const status = currentSession.value.status
  const classes = {
    ready: 'bg-green-400',
    analyzing: 'bg-blue-400 animate-pulse',
    paused: 'bg-yellow-400',
    error: 'bg-red-400',
  }
  return classes[status] || 'bg-gray-400'
})

const sessionStatusText = computed(() => {
  if (!currentSession.value) return ''
  const status = currentSession.value.status
  const texts = {
    initializing: '初始化中',
    ready: '就绪',
    analyzing: '分析中',
    paused: '已暂停',
    completed: '已完成',
    error: '错误',
  }
  return texts[status] || status
})

const filteredChains = computed(() => {
  if (!searchQuery.value) return chainContexts.value
  const q = searchQuery.value.toLowerCase()
  return chainContexts.value.filter(c =>
    c.sink_site.symbol.toLowerCase().includes(q) ||
    c.sink_site.file_path.toLowerCase().includes(q)
  )
})

const filteredSinks = computed(() => {
  if (!searchQuery.value) return sinkSites.value
  const q = searchQuery.value.toLowerCase()
  return sinkSites.value.filter(s =>
    s.symbol.toLowerCase().includes(q) ||
    s.file_path.toLowerCase().includes(q)
  )
})

const filteredUnits = computed(() => {
  if (!searchQuery.value) return codeUnits.value
  const q = searchQuery.value.toLowerCase()
  return codeUnits.value.filter(u =>
    u.symbol.toLowerCase().includes(q) ||
    u.file_path.toLowerCase().includes(q)
  )
})

const currentFindings = computed(() => {
  if (findingTab.value === 'pending') return pendingFindings.value
  if (findingTab.value === 'confirmed') return confirmedFindings.value
  return rejectedFindings.value
})

// ============ 方法 ============

// 辅助函数：添加发现到待确认列表（避免重复）
const addFindingsToList = (findings) => {
  if (!findings || findings.length === 0) return

  const existingIds = new Set(pendingFindings.value.map(f => f.id))
  const newFindings = findings.filter(f => !existingIds.has(f.id))
  if (newFindings.length > 0) {
    pendingFindings.value.push(...newFindings)
  }
}

// 会话管理
const fetchExistingSessions = async () => {
  try {
    const result = await api.listInteractiveSessions()
    if (result.success) {
      existingSessions.value = result.data.sessions || []
    }
  } catch (error) {
    console.error('获取会话列表失败:', error)
  }
}

const createSession = async () => {
  if (!newSessionConfig.targetPath) return

  isCreatingSession.value = true
  try {
    const result = await api.createInteractiveSession({
      target_path: newSessionConfig.targetPath,
      languages: newSessionConfig.languages.length > 0 ? newSessionConfig.languages : null,
      max_chain_depth: newSessionConfig.maxChainDepth,
      skip_index: true,
    })

    if (result.success) {
      currentSession.value = result.data
      await loadSessionData(result.data.session_id)
      connectWebSocket(result.data.session_id)
    }
  } catch (error) {
    console.error('创建会话失败:', error)
    alert('创建会话失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    isCreatingSession.value = false
  }
}

const loadSession = async (sessionId) => {
  try {
    const result = await api.getInteractiveSession(sessionId)
    if (result.success) {
      currentSession.value = result.data
      await loadSessionData(sessionId)
      connectWebSocket(sessionId)
    }
  } catch (error) {
    console.error('加载会话失败:', error)
    alert('加载会话失败')
  }
}

const loadSessionData = async (sessionId) => {
  try {
    // M-8 修复: 使用 Promise.allSettled 防止单个请求失败导致全部失败
    const results = await Promise.allSettled([
      api.listChainContexts(sessionId),
      api.listSinkSites(sessionId),
      api.listCodeUnits(sessionId),
      api.getFindings(sessionId),
    ])

    // 提取成功的结果（失败的返回 { success: false }）
    const [chainsResult, sinksResult, unitsResult, findingsResult] = results.map(
      r => r.status === 'fulfilled' ? r.value : { success: false }
    )

    if (chainsResult.success) {
      chainContexts.value = chainsResult.data.chain_contexts || []
    }
    if (sinksResult.success) {
      sinkSites.value = sinksResult.data.sink_sites || []
    }
    if (unitsResult.success) {
      codeUnits.value = unitsResult.data.code_units || []
    }
    if (findingsResult.success) {
      pendingFindings.value = findingsResult.data.pending || []
      confirmedFindings.value = findingsResult.data.confirmed || []
      rejectedFindings.value = findingsResult.data.rejected || []
    }
  } catch (error) {
    console.error('加载会话数据失败:', error)
  }
}

const deleteSession = async (sessionId) => {
  if (!confirm('确定要删除该会话吗？')) return

  try {
    await api.deleteInteractiveSession(sessionId)
    existingSessions.value = existingSessions.value.filter(s => s.session_id !== sessionId)
    if (currentSession.value?.session_id === sessionId) {
      currentSession.value = null
      disconnectWebSocket()
      resetFCState()
    }
  } catch (error) {
    console.error('删除会话失败:', error)
  }
}

const deleteCurrentSession = () => {
  if (currentSession.value) {
    deleteSession(currentSession.value.session_id)
  }
}

// 代码浏览
const toggleChainSelection = (chainId) => {
  const index = selectedChainIds.value.indexOf(chainId)
  if (index > -1) {
    selectedChainIds.value.splice(index, 1)
  } else {
    selectedChainIds.value.push(chainId)
  }
}

const toggleUnitSelection = (unitId) => {
  const index = selectedUnitIds.value.indexOf(unitId)
  if (index > -1) {
    selectedUnitIds.value.splice(index, 1)
  } else {
    selectedUnitIds.value.push(unitId)
  }
}

const clearSelection = () => {
  selectedChainIds.value = []
  selectedUnitIds.value = []
}

const viewSinkDetail = (sink) => {
  // 可以显示详情弹窗或跳转
  console.log('View sink:', sink)
}

// LLM 交互
const analyzeSelected = async () => {
  if (!currentSession.value) return
  if (selectedChainIds.value.length === 0 && selectedUnitIds.value.length === 0) {
    alert('请先选择要分析的调用链或代码单元')
    return
  }

  isAnalyzing.value = true
  currentAnalysisStep.value = '正在准备分析...'
  resetFCState()

  // 添加用户消息
  chatMessages.value.push({
    role: 'user',
    content: `分析选中的 ${selectedChainIds.value.length} 条调用链和 ${selectedUnitIds.value.length} 个代码单元`,
    timestamp: new Date(),
  })

  try {
    const result = await api.analyzeSelection({
      session_id: currentSession.value.session_id,
      selected_chain_ids: selectedChainIds.value,
      selected_unit_ids: selectedUnitIds.value,
    })

    if (result.success) {
      // 添加 LLM 响应
      chatMessages.value.push({
        role: 'assistant',
        content: result.data.content,
        findings: result.data.findings || [],
        timestamp: new Date(),
      })

      // 更新发现列表（避免重复添加）
      addFindingsToList(result.data.findings)

      scrollToBottom()
    }
  } catch (error) {
    console.error('分析失败:', error)
    chatMessages.value.push({
      role: 'assistant',
      content: '分析失败: ' + (error.response?.data?.detail || error.message),
      timestamp: new Date(),
    })
  } finally {
    isAnalyzing.value = false
    currentAnalysisStep.value = ''
  }
}

const sendChatMessage = async () => {
  if (!chatInput.value.trim() || !currentSession.value || isAnalyzing.value) return

  const message = chatInput.value.trim()
  chatInput.value = ''

  chatMessages.value.push({
    role: 'user',
    content: message,
    timestamp: new Date(),
  })

  isAnalyzing.value = true
  currentAnalysisStep.value = '正在等待 LLM 响应...'

  try {
    const result = await api.chatWithLLM({
      session_id: currentSession.value.session_id,
      message: message,
    })

    if (result.success) {
      chatMessages.value.push({
        role: 'assistant',
        content: result.data.content,
        findings: result.data.findings || [],
        timestamp: new Date(),
      })

      // 更新发现列表（避免重复添加）
      addFindingsToList(result.data.findings)

      scrollToBottom()
    }
  } catch (error) {
    console.error('对话失败:', error)
    chatMessages.value.push({
      role: 'assistant',
      content: '对话失败: ' + (error.response?.data?.detail || error.message),
      timestamp: new Date(),
    })
  } finally {
    isAnalyzing.value = false
    currentAnalysisStep.value = ''
  }
}

const generateSummary = async () => {
  if (!currentSession.value || isAnalyzing.value) return

  isAnalyzing.value = true
  currentAnalysisStep.value = '正在生成总结报告...'

  try {
    const result = await api.summarizeSession(currentSession.value.session_id)

    if (result.success) {
      chatMessages.value.push({
        role: 'assistant',
        content: result.data.content,
        timestamp: new Date(),
      })
      scrollToBottom()
    }
  } catch (error) {
    console.error('生成总结失败:', error)
  } finally {
    isAnalyzing.value = false
    currentAnalysisStep.value = ''
  }
}

const stopCurrentAnalysis = async () => {
  if (!currentSession.value) return

  try {
    await api.stopAnalysis(currentSession.value.session_id)
    isAnalyzing.value = false
    currentAnalysisStep.value = ''
  } catch (error) {
    console.error('停止分析失败:', error)
  }
}

// 发现管理
const confirmFindingAction = async (findingId) => {
  if (!currentSession.value) return

  const notes = prompt('请输入确认备注（可选）:')

  try {
    await api.confirmFinding(currentSession.value.session_id, findingId, notes || '')

    // 移动发现到已确认列表
    const finding = pendingFindings.value.find(f => f.id === findingId)
    if (finding) {
      finding.status = 'confirmed'
      finding.user_notes = notes || ''
      pendingFindings.value = pendingFindings.value.filter(f => f.id !== findingId)
      confirmedFindings.value.push(finding)
    }
  } catch (error) {
    console.error('确认发现失败:', error)
  }
}

const rejectFindingAction = async (findingId) => {
  if (!currentSession.value) return

  const reason = prompt('请输入拒绝原因（可选）:')

  try {
    await api.rejectFinding(currentSession.value.session_id, findingId, reason || '')

    // 移动发现到已拒绝列表
    const finding = pendingFindings.value.find(f => f.id === findingId)
    if (finding) {
      finding.status = 'rejected'
      finding.rejected_reason = reason || ''
      pendingFindings.value = pendingFindings.value.filter(f => f.id !== findingId)
      rejectedFindings.value.push(finding)
    }
  } catch (error) {
    console.error('拒绝发现失败:', error)
  }
}

const digDeeperAction = async (findingId) => {
  if (!currentSession.value || isAnalyzing.value) return

  isAnalyzing.value = true
  currentAnalysisStep.value = '正在深入分析...'

  chatMessages.value.push({
    role: 'user',
    content: `深入分析发现 ${findingId}`,
    timestamp: new Date(),
  })

  try {
    const result = await api.digDeeper({
      session_id: currentSession.value.session_id,
      finding_id: findingId,
      direction: 'expand',
    })

    if (result.success) {
      chatMessages.value.push({
        role: 'assistant',
        content: result.data.content,
        findings: result.data.findings || [],
        timestamp: new Date(),
      })

      // 更新发现列表（避免重复添加）
      addFindingsToList(result.data.findings)

      scrollToBottom()
    }
  } catch (error) {
    console.error('深入分析失败:', error)
    chatMessages.value.push({
      role: 'assistant',
      content: '深入分析失败: ' + (error.response?.data?.detail || error.message),
      timestamp: new Date(),
    })
  } finally {
    isAnalyzing.value = false
    currentAnalysisStep.value = ''
  }
}

// WebSocket
let wsReconnectTimer = null
let wsReconnectAttempts = 0
const WS_MAX_RECONNECT_ATTEMPTS = 5
const WS_RECONNECT_DELAY = 3000

const connectWebSocket = (sessionId) => {
  // 清理之前的重连计时器
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer)
    wsReconnectTimer = null
  }

  try {
    // 先关闭旧连接（标记为主动关闭，避免 onclose 触发自动重连）
    if (ws) {
      try {
        ws.__manualClose = true
        ws.onopen = null
        ws.onmessage = null
        ws.onerror = null
        ws.onclose = null
        ws.close(1000, 'Reconnecting')
      } catch (e) {
        // ignore
      }
      ws = null
    }

    const wsInstance = api.createInteractiveWebSocket(sessionId)
    wsInstance.__manualClose = false
    ws = wsInstance

    wsInstance.onopen = () => {
      console.log('WebSocket connected')
      wsReconnectAttempts = 0  // 重置重连计数
    }

    wsInstance.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        handleWebSocketMessage(data)
      } catch (e) {
        console.error('WebSocket message parse error:', e)
      }
    }

    wsInstance.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    wsInstance.onclose = (event) => {
      console.log('WebSocket disconnected, code:', event.code)
      // 主动关闭时，清理 ws 引用并返回，不进行重连
      if (wsInstance.__manualClose) {
        if (ws === wsInstance) {
          ws = null
        }
        return
      }
      // 非正常关闭且会话仍存在时尝试重连
      const isCurrentSession = currentSession.value && currentSession.value.session_id === sessionId
      if (isCurrentSession && event.code !== 1000 && wsReconnectAttempts < WS_MAX_RECONNECT_ATTEMPTS) {
        wsReconnectAttempts++
        console.log(`WebSocket reconnecting... attempt ${wsReconnectAttempts}/${WS_MAX_RECONNECT_ATTEMPTS}`)
        wsReconnectTimer = setTimeout(() => {
          connectWebSocket(sessionId)
        }, WS_RECONNECT_DELAY)
      }
    }
  } catch (error) {
    console.error('WebSocket connection failed:', error)
  }
}

const disconnectWebSocket = () => {
  // 清理重连计时器
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer)
    wsReconnectTimer = null
  }
  wsReconnectAttempts = 0

  if (ws) {
    try {
      ws.__manualClose = true
      ws.onopen = null
      ws.onmessage = null
      ws.onerror = null
      ws.onclose = null
      ws.close(1000, 'User disconnect')
    } catch (e) {
      // ignore
    }
    ws = null
  }
}

const handleWebSocketMessage = (data) => {
  switch (data.type) {
    case 'status':
      if (currentSession.value) {
        currentSession.value.status = data.status
      }
      break
    case 'finding':
      // 使用辅助函数避免重复添加
      if (data.finding) {
        addFindingsToList([data.finding])
        fcState.findingsCount++
      }
      break
    case 'progress':
      currentAnalysisStep.value = data.current_step || ''
      break
    // FC 相关消息处理
    case 'fc_tool_call':
      handleFCToolCall(data)
      break
    case 'fc_llm_thinking':
      handleFCLLMThinking(data)
      break
    case 'fc_turn_complete':
      handleFCTurnComplete(data)
      break
    case 'fc_analysis_complete':
      handleFCAnalysisComplete(data)
      break
  }
}

// FC 工具调用处理
const handleFCToolCall = (data) => {
  // 使用 auditStore 的统一处理函数，传入本地 fcState
  auditStore.processFCToolCallMessage(data, fcState)
}

// FC LLM 思考处理
const handleFCLLMThinking = (data) => {
  fcState.enabled = true
  fcState.status = 'analyzing'

  if (data.sink_symbol) {
    fcState.currentSink = data.sink_symbol
  }

  if (data.message) {
    currentAnalysisStep.value = data.message
  }
}

// FC 轮次完成处理
const handleFCTurnComplete = (data) => {
  if (data.turn !== undefined) {
    fcState.currentTurn = data.turn
  }
}

// FC 分析完成处理
const handleFCAnalysisComplete = (data) => {
  fcState.status = data.success ? 'completed' : 'failed'
  if (data.findings_count !== undefined) {
    fcState.findingsCount = data.findings_count
  }
}

// 工具函数
const scrollToBottom = () => {
  nextTick(() => {
    if (chatContainer.value) {
      chatContainer.value.scrollTop = chatContainer.value.scrollHeight
    }
  })
}

const formatDate = (dateStr) => {
  const date = new Date(dateStr)
  return date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const formatTime = (date) => {
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
}

const renderMarkdown = (text) => {
  // 简单的 Markdown 渲染
  if (!text) return ''
  return text
    .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre class="bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto text-xs"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-100 px-1 rounded text-sm">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')
}

const getSessionBadgeClass = (status) => {
  const classes = {
    ready: 'bg-green-100 text-green-700',
    analyzing: 'bg-blue-100 text-blue-700',
    paused: 'bg-yellow-100 text-yellow-700',
    error: 'bg-red-100 text-red-700',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
}

const getSessionStatusText = (status) => {
  const texts = {
    initializing: '初始化中',
    ready: '就绪',
    analyzing: '分析中',
    paused: '已暂停',
    completed: '已完成',
    error: '错误',
  }
  return texts[status] || status
}

const getRiskBadgeClass = (level) => {
  const classes = {
    high: 'bg-red-100 text-red-600',
    medium: 'bg-orange-100 text-orange-600',
    low: 'bg-yellow-100 text-yellow-600',
  }
  return classes[level] || 'bg-gray-100 text-gray-600'
}

const getFindingSeverityClass = (severity) => {
  const classes = {
    critical: 'border-red-500 bg-red-50',
    high: 'border-orange-500 bg-orange-50',
    medium: 'border-yellow-500 bg-yellow-50',
    low: 'border-blue-500 bg-blue-50',
  }
  return classes[severity] || 'border-gray-300 bg-gray-50'
}

const getSeverityBadgeClass = (severity) => {
  const classes = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-white',
    low: 'bg-blue-500 text-white',
  }
  return classes[severity] || 'bg-gray-500 text-white'
}

const getFindingCardClass = (finding) => {
  const base = 'border-l-4'
  if (finding.status === 'confirmed') {
    return `${base} border-green-500 bg-green-50`
  } else if (finding.status === 'rejected') {
    return `${base} border-gray-400 bg-gray-50`
  }
  return `${base} ${getFindingSeverityClass(finding.severity)}`
}

// ============ 生命周期 ============

onMounted(() => {
  fetchExistingSessions()
})

// 路由离开前清理资源，避免后台持续重连导致卡顿
onBeforeRouteLeave(() => {
  disconnectWebSocket()
})

onUnmounted(() => {
  disconnectWebSocket()
})

// 监听对话变化，自动滚动到底部
watch(chatMessages, () => {
  scrollToBottom()
}, { deep: true })
</script>

<style scoped>
.lang-chip {
  @apply flex items-center gap-2 px-4 py-2.5 rounded-xl cursor-pointer transition-all duration-200;
  background: rgba(255, 255, 255, 0.4);
  border: 2px solid transparent;
}

.lang-chip:hover {
  background: rgba(255, 255, 255, 0.6);
}

.lang-chip.active {
  background: rgba(59, 130, 246, 0.1);
  border-color: rgb(59, 130, 246);
}

.chain-item.selected,
.unit-item.selected {
  background: rgba(139, 92, 246, 0.15);
  border: 1px solid rgba(139, 92, 246, 0.3);
}

.chat-message {
  @apply p-4 rounded-xl;
}

.chat-message.user {
  @apply bg-blue-500/10 ml-8;
}

.chat-message.assistant {
  @apply bg-white/50 mr-8;
}

.message-header {
  @apply flex items-center justify-between mb-2;
}

.message-role {
  @apply text-xs font-medium text-gray-500;
}

.message-time {
  @apply text-xs text-gray-400;
}

.message-content {
  @apply text-sm text-gray-700 leading-relaxed;
}

.finding-card {
  @apply transition-all;
}

.finding-detail-card {
  background: rgba(255, 255, 255, 0.5);
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
</style>
