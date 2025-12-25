<template>
  <div class="space-y-6">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2">开始扫描</h1>
        <p class="text-white/60">配置并启动代码安全扫描任务</p>
      </div>
      <div v-if="currentScan && currentScan.status !== 'completed'" class="flex items-center gap-2">
        <div class="flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-500/20 text-blue-300">
          <div class="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></div>
          <span class="text-sm font-medium">扫描进行中</span>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 扫描配置表单 -->
      <div class="lg:col-span-2 space-y-6">
        <div class="glass-card rounded-2xl p-6">
          <div class="flex items-center gap-3 mb-6">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-lg font-semibold text-gray-800">扫描配置</h2>
              <p class="text-sm text-gray-500">配置扫描参数</p>
            </div>
          </div>

          <form @submit.prevent="startScan" class="space-y-6">
            <!-- 目标路径 -->
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                <span class="flex items-center gap-2">
                  <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                  </svg>
                  目标路径
                </span>
              </label>
              <div class="flex gap-3">
                <input
                  v-model="config.targetPath"
                  type="text"
                  class="input-glass flex-1"
                  placeholder="输入项目路径，例如: /path/to/project"
                />
                <button type="button" class="btn-secondary px-4" @click="browsePath">
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z"/>
                  </svg>
                </button>
              </div>
            </div>

            <!-- 语言选择 -->
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-3">
                <span class="flex items-center gap-2">
                  <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                  </svg>
                  扫描语言
                </span>
              </label>
              <div class="flex flex-wrap gap-3">
                <label
                  v-for="lang in availableLanguages"
                  :key="lang.value"
                  class="lang-chip group"
                  :class="{ active: config.languages.includes(lang.value) }"
                >
                  <input
                    type="checkbox"
                    :value="lang.value"
                    v-model="config.languages"
                    class="hidden"
                  />
                  <span class="lang-icon" :class="lang.iconClass">{{ lang.icon }}</span>
                  <span>{{ lang.label }}</span>
                  <svg v-if="config.languages.includes(lang.value)" class="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                  </svg>
                </label>
              </div>
            </div>

            <!-- 漏洞类型 -->
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-3">
                <span class="flex items-center gap-2">
                  <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                  </svg>
                  漏洞类型
                </span>
              </label>
              <div class="flex flex-wrap gap-2">
                <label
                  v-for="vt in vulnTypes"
                  :key="vt.value"
                  class="vuln-chip"
                  :class="{ active: config.vulnTypes.includes(vt.value) }"
                >
                  <input
                    type="checkbox"
                    :value="vt.value"
                    v-model="config.vulnTypes"
                    class="hidden"
                  />
                  <span class="vuln-dot" :class="vt.colorClass"></span>
                  <span>{{ vt.label }}</span>
                </label>
              </div>
              <div class="flex gap-2 mt-3">
                <button type="button" @click="selectAllVulnTypes" class="text-xs text-blue-600 hover:text-blue-700">
                  全选
                </button>
                <span class="text-gray-300">|</span>
                <button type="button" @click="clearVulnTypes" class="text-xs text-gray-500 hover:text-gray-700">
                  清空
                </button>
              </div>
            </div>

            <!-- 高级选项 -->
            <div class="space-y-4">
              <div class="flex items-center justify-between">
                <label class="text-sm font-medium text-gray-700 flex items-center gap-2">
                  <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
                  </svg>
                  高级选项
                </label>
                <button
                  type="button"
                  @click="showAdvanced = !showAdvanced"
                  class="text-sm text-blue-600 hover:text-blue-700"
                >
                  {{ showAdvanced ? '收起' : '展开' }}
                </button>
              </div>

              <transition name="slide">
                <div v-if="showAdvanced" class="grid grid-cols-2 gap-4">
                  <label class="option-card">
                    <input type="checkbox" v-model="config.useLLM" class="hidden" />
                    <div class="option-checkbox" :class="{ checked: config.useLLM }">
                      <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                    </div>
                    <div>
                      <span class="text-sm font-medium text-gray-800">LLM 深度分析</span>
                      <p class="text-xs text-gray-500">使用 AI 进行深度漏洞验证</p>
                    </div>
                  </label>

                  <label class="option-card">
                    <input type="checkbox" v-model="config.scanLogic" class="hidden" />
                    <div class="option-checkbox" :class="{ checked: config.scanLogic }">
                      <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                    </div>
                    <div>
                      <span class="text-sm font-medium text-gray-800">业务逻辑扫描</span>
                      <p class="text-xs text-gray-500">检测权限、流程等逻辑漏洞</p>
                    </div>
                  </label>

                  <label class="option-card">
                    <input type="checkbox" v-model="config.useChainAnalysis" class="hidden" />
                    <div class="option-checkbox" :class="{ checked: config.useChainAnalysis }">
                      <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                    </div>
                    <div>
                      <span class="text-sm font-medium text-gray-800">链级分析（推荐）</span>
                      <p class="text-xs text-gray-500">追踪调用链 + 污点传播，P0级推荐流程</p>
                    </div>
                  </label>

                  <label class="option-card">
                    <input type="checkbox" v-model="config.reindex" class="hidden" />
                    <div class="option-checkbox" :class="{ checked: config.reindex }">
                      <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                    </div>
                    <div>
                      <span class="text-sm font-medium text-gray-800">重新索引</span>
                      <p class="text-xs text-gray-500">扫描前重建代码向量索引</p>
                    </div>
                  </label>

                  <label class="option-card col-span-2">
                    <input type="checkbox" v-model="config.skipIndex" class="hidden" />
                    <div class="option-checkbox" :class="{ checked: config.skipIndex }">
                      <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                    </div>
                    <div>
                      <span class="text-sm font-medium text-gray-800">跳过向量索引（小项目推荐）</span>
                      <p class="text-xs text-gray-500">直接遍历代码文件分析，不使用向量数据库索引。适合代码量较小的项目，速度更快。</p>
                    </div>
                  </label>

                  <div class="col-span-2 grid grid-cols-2 gap-4">
                    <div class="p-4 rounded-xl bg-white/30">
                      <label class="text-sm font-medium text-gray-700 block mb-2">最大分析数</label>
                      <input
                        type="number"
                        v-model="config.maxIssues"
                        min="10"
                        max="200"
                        class="w-full px-3 py-2 rounded-lg bg-white/50 border border-white/30 outline-none focus:border-blue-400"
                      />
                    </div>
                    <div class="p-4 rounded-xl bg-white/30">
                      <label class="text-sm font-medium text-gray-700 block mb-2">调用链深度</label>
                      <input
                        type="number"
                        v-model="config.maxChainDepth"
                        min="1"
                        max="15"
                        class="w-full px-3 py-2 rounded-lg bg-white/50 border border-white/30 outline-none focus:border-blue-400"
                      />
                      <p class="text-xs text-gray-500 mt-1">链级分析的最大追溯深度</p>
                    </div>
                  </div>
                </div>
              </transition>
            </div>

            <!-- 提交按钮 -->
            <div class="flex justify-end gap-4 pt-4 border-t border-gray-200/50">
              <button type="button" class="btn-secondary" @click="resetConfig">
                重置配置
              </button>
              <button
                type="submit"
                class="btn-primary flex items-center gap-2"
                :disabled="isScanning || !config.targetPath"
              >
                <svg v-if="isScanning" class="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <span>{{ isScanning ? '启动中...' : '开始扫描' }}</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      <!-- 扫描状态面板 -->
      <div class="space-y-6">
        <!-- 扫描进度卡片 -->
        <div class="glass-card rounded-2xl p-6">
          <div class="flex items-center gap-3 mb-6">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center">
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-lg font-semibold text-gray-800">扫描状态</h2>
              <p class="text-sm text-gray-500">实时进度监控</p>
            </div>
          </div>

          <div v-if="currentScan" class="space-y-6">
            <!-- 状态指示 -->
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <div class="relative">
                  <div
                    class="w-4 h-4 rounded-full"
                    :class="getStatusColor(currentScan.status)"
                  ></div>
                  <div
                    v-if="currentScan.status === 'analyzing' || currentScan.status === 'indexing'"
                    class="absolute inset-0 rounded-full animate-ping"
                    :class="getStatusColor(currentScan.status)"
                    style="animation-duration: 2s;"
                  ></div>
                </div>
                <span class="font-medium text-gray-800">{{ getStatusText(currentScan.status) }}</span>
              </div>
              <span
                class="px-2 py-1 rounded-full text-xs font-medium"
                :class="getStatusBadgeClass(currentScan.status)"
              >
                {{ Math.round(currentScan.progress * 100) }}%
              </span>
            </div>

            <!-- 圆形进度 -->
            <div class="flex justify-center">
              <div class="relative">
                <svg class="w-32 h-32 transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="none"
                    stroke="rgba(0,0,0,0.05)"
                    stroke-width="8"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="none"
                    :stroke="getProgressColor(currentScan.status)"
                    stroke-width="8"
                    stroke-linecap="round"
                    :stroke-dasharray="`${currentScan.progress * 352} 352`"
                    class="transition-all duration-500"
                  />
                </svg>
                <div class="absolute inset-0 flex flex-col items-center justify-center">
                  <svg v-if="currentScan.status === 'completed'" class="w-10 h-10 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                  </svg>
                  <svg v-else-if="currentScan.status === 'failed'" class="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                  <svg v-else class="w-10 h-10 text-blue-500 spinner" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                </div>
              </div>
            </div>

            <!-- 当前步骤 -->
            <div class="text-center">
              <p class="text-sm text-gray-600">{{ currentScan.current_step || '准备中...' }}</p>
            </div>

            <!-- 步骤指示器 -->
            <div class="flex justify-between items-center">
              <div
                v-for="(step, index) in scanSteps"
                :key="step.key"
                class="flex flex-col items-center"
              >
                <div
                  class="w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium transition-all"
                  :class="getStepClass(step.key)"
                >
                  <svg v-if="isStepCompleted(step.key)" class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                  </svg>
                  <span v-else>{{ index + 1 }}</span>
                </div>
                <span class="text-xs text-gray-500 mt-1">{{ step.label }}</span>
              </div>
            </div>

            <!-- 统计数据 -->
            <div class="grid grid-cols-2 gap-4">
              <div class="p-4 rounded-xl bg-gradient-to-br from-orange-50 to-orange-100/50 text-center">
                <div class="text-2xl font-bold text-orange-600">{{ currentScan.findings?.length || 0 }}</div>
                <div class="text-xs text-orange-600/70">安全问题</div>
              </div>
              <div class="p-4 rounded-xl bg-gradient-to-br from-red-50 to-red-100/50 text-center">
                <div class="text-2xl font-bold text-red-600">{{ currentScan.vuln_findings?.length || 0 }}</div>
                <div class="text-xs text-red-600/70">高危漏洞</div>
              </div>
            </div>

            <!-- 操作按钮 -->
            <div class="space-y-3">
              <button
                v-if="currentScan.status === 'completed'"
                @click="viewResults"
                class="btn-primary w-full flex items-center justify-center gap-2"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                查看详细结果
              </button>
              <button
                v-if="currentScan.status !== 'completed' && currentScan.status !== 'failed'"
                @click="cancelScan"
                class="btn-secondary w-full text-red-600"
              >
                取消扫描
              </button>
            </div>
          </div>

          <!-- 空状态 -->
          <div v-else class="text-center py-12">
            <div class="w-20 h-20 mx-auto mb-4 rounded-full bg-gray-100 flex items-center justify-center">
              <svg class="w-10 h-10 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
            </div>
            <p class="text-gray-500 mb-2">暂无扫描任务</p>
            <p class="text-sm text-gray-400">配置参数后开始扫描</p>
          </div>
        </div>

        <!-- 扫描日志 -->
        <div v-if="currentScan && logs.length > 0" class="glass-card rounded-2xl p-6">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-sm font-semibold text-gray-800">扫描日志</h3>
            <button @click="clearLogs" class="text-xs text-gray-500 hover:text-gray-700">
              清空
            </button>
          </div>
          <div class="h-48 overflow-y-auto space-y-1 font-mono text-xs bg-gray-900/90 rounded-xl p-3">
            <div
              v-for="(log, index) in logs"
              :key="index"
              class="flex gap-2"
              :class="getLogClass(log.level)"
            >
              <span class="text-gray-500 shrink-0">{{ log.time }}</span>
              <span>{{ log.message }}</span>
            </div>
          </div>
        </div>

        <!-- LLM 交互时间线 -->
        <div v-if="currentScan && interactions.length > 0" class="glass-card rounded-2xl p-6">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-sm font-semibold text-gray-800 flex items-center gap-2">
              <svg class="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
              </svg>
              LLM 分析过程
            </h3>
            <div class="flex items-center gap-3">
              <span class="text-xs text-gray-500">{{ interactions.length }} 条记录</span>
              <button @click="clearInteractions" class="text-xs text-gray-500 hover:text-gray-700">
                清空
              </button>
            </div>
          </div>
          <div class="h-64 overflow-y-auto space-y-2">
            <div
              v-for="(interaction, index) in interactions"
              :key="index"
              class="p-3 rounded-lg border-l-4 transition-all hover:shadow-sm"
              :class="getInteractionClass(interaction.type)"
            >
              <div class="flex items-start justify-between">
                <div class="flex items-center gap-2">
                  <span class="text-lg">{{ getInteractionIcon(interaction.type) }}</span>
                  <div>
                    <span class="text-sm font-medium text-gray-800">{{ interaction.title }}</span>
                    <span v-if="interaction.tool_name" class="text-xs text-gray-500 ml-2">
                      ({{ interaction.tool_name }})
                    </span>
                  </div>
                </div>
                <div class="flex items-center gap-2 text-xs text-gray-500">
                  <span v-if="interaction.duration_ms" class="px-1.5 py-0.5 rounded bg-white/50">
                    {{ formatDuration(interaction.duration_ms) }}
                  </span>
                  <span v-if="interaction.tokens_used" class="px-1.5 py-0.5 rounded bg-white/50">
                    {{ interaction.tokens_used }} tokens
                  </span>
                </div>
              </div>
              <div v-if="interaction.content" class="mt-2 text-xs text-gray-600 line-clamp-2">
                {{ typeof interaction.content === 'string' ? interaction.content : JSON.stringify(interaction.content).slice(0, 150) }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAppStore } from '../stores/app'
import * as api from '../api'

const router = useRouter()
const appStore = useAppStore()

const showAdvanced = ref(true)
const logs = ref([])
const interactions = ref([])  // LLM 交互日志

const availableLanguages = [
  { value: 'python', label: 'Python', icon: 'Py', iconClass: 'bg-blue-500' },
  { value: 'javascript', label: 'JavaScript', icon: 'JS', iconClass: 'bg-yellow-500' },
  { value: 'typescript', label: 'TypeScript', icon: 'TS', iconClass: 'bg-blue-600' },
  { value: 'php', label: 'PHP', icon: 'PHP', iconClass: 'bg-purple-500' },
]

const vulnTypes = [
  { value: 'rce', label: 'RCE', colorClass: 'bg-red-500' },
  { value: 'command_injection', label: '命令注入', colorClass: 'bg-red-400' },
  { value: 'sql_injection', label: 'SQL 注入', colorClass: 'bg-orange-500' },
  { value: 'file_read', label: '文件读取', colorClass: 'bg-orange-400' },
  { value: 'file_write', label: '文件写入', colorClass: 'bg-orange-400' },
  { value: 'ssrf', label: 'SSRF', colorClass: 'bg-yellow-500' },
  { value: 'ssti', label: 'SSTI', colorClass: 'bg-purple-500' },
  { value: 'deserialization', label: '反序列化', colorClass: 'bg-purple-400' },
  { value: 'auth_bypass', label: '认证绕过', colorClass: 'bg-pink-500' },
  { value: 'idor', label: 'IDOR', colorClass: 'bg-pink-400' },
  { value: 'logic_flaw', label: '逻辑漏洞', colorClass: 'bg-indigo-500' },
]

const scanSteps = [
  { key: 'indexing', label: '索引' },
  { key: 'analyzing', label: '分析' },
  { key: 'detecting', label: '检测' },
  { key: 'completed', label: '完成' },
]

const config = reactive({
  targetPath: '',
  languages: [],
  vulnTypes: ['rce', 'command_injection', 'sql_injection'],
  useLLM: true,
  scanLogic: true,
  useChainAnalysis: true,
  reindex: false,
  skipIndex: false,
  maxIssues: 50,
  maxChainDepth: 5,
})

const isScanning = ref(false)
const currentScan = ref(null)
let ws = null
let pollInterval = null

const getStatusColor = (status) => {
  const colors = {
    completed: 'bg-green-500',
    analyzing: 'bg-blue-500',
    indexing: 'bg-yellow-500',
    detecting: 'bg-purple-500',
    pending: 'bg-gray-400',
    failed: 'bg-red-500',
  }
  return colors[status] || 'bg-gray-400'
}

const getProgressColor = (status) => {
  const colors = {
    completed: '#34C759',
    analyzing: '#007AFF',
    indexing: '#FF9500',
    detecting: '#AF52DE',
    pending: '#8E8E93',
    failed: '#FF3B30',
  }
  return colors[status] || '#8E8E93'
}

const getStatusText = (status) => {
  const texts = {
    completed: '扫描完成',
    analyzing: '分析中',
    indexing: '索引中',
    detecting: '漏洞检测中',
    pending: '准备中',
    failed: '扫描失败',
  }
  return texts[status] || status
}

const getStatusBadgeClass = (status) => {
  const classes = {
    completed: 'bg-green-100 text-green-700',
    analyzing: 'bg-blue-100 text-blue-700',
    indexing: 'bg-yellow-100 text-yellow-700',
    detecting: 'bg-purple-100 text-purple-700',
    pending: 'bg-gray-100 text-gray-600',
    failed: 'bg-red-100 text-red-700',
  }
  return classes[status] || 'bg-gray-100 text-gray-600'
}

const getStepClass = (stepKey) => {
  if (!currentScan.value) return 'bg-gray-200 text-gray-500'

  const stepOrder = ['pending', 'indexing', 'analyzing', 'detecting', 'completed']
  const currentIndex = stepOrder.indexOf(currentScan.value.status)
  const stepIndex = stepOrder.indexOf(stepKey)

  if (stepIndex < currentIndex || currentScan.value.status === 'completed') {
    return 'bg-green-500 text-white'
  } else if (stepIndex === currentIndex) {
    return 'bg-blue-500 text-white'
  }
  return 'bg-gray-200 text-gray-500'
}

const isStepCompleted = (stepKey) => {
  if (!currentScan.value) return false
  const stepOrder = ['pending', 'indexing', 'analyzing', 'detecting', 'completed']
  const currentIndex = stepOrder.indexOf(currentScan.value.status)
  const stepIndex = stepOrder.indexOf(stepKey)
  return stepIndex < currentIndex || currentScan.value.status === 'completed'
}

const getLogClass = (level) => {
  const classes = {
    info: 'text-blue-400',
    warning: 'text-yellow-400',
    error: 'text-red-400',
    success: 'text-green-400',
  }
  return classes[level] || 'text-gray-300'
}

const addLog = (message, level = 'info', append = false) => {
  const now = new Date()
  const time = now.toTimeString().split(' ')[0]

  // 流式追加模式：将内容追加到最后一条日志
  if (append && logs.value.length > 0) {
    const lastLog = logs.value[logs.value.length - 1]
    if (lastLog.level === level) {
      lastLog.message += message
      return
    }
  }

  logs.value.push({ time, message, level })
  if (logs.value.length > 100) {
    logs.value.shift()
  }
}

const clearLogs = () => {
  logs.value = []
}

// LLM 交互日志处理
const handleInteraction = (interaction) => {
  interactions.value.push(interaction)
  // 限制显示数量
  if (interactions.value.length > 50) {
    interactions.value.shift()
  }
  // 同时添加到日志
  const logLevel = interaction.type === 'finding' ? 'success' : 'info'
  addLog(`[${getInteractionTypeName(interaction.type)}] ${interaction.title}`, logLevel)
}

const getInteractionTypeName = (type) => {
  const names = {
    'tool_call': '工具调用',
    'thinking': 'LLM思考',
    'analysis': 'LLM分析',
    'finding': '发现问题',
  }
  return names[type] || type
}

const getInteractionIcon = (type) => {
  const icons = {
    'tool_call': '🔧',
    'thinking': '💭',
    'analysis': '🔍',
    'finding': '⚠️',
  }
  return icons[type] || '📝'
}

const getInteractionClass = (type) => {
  const classes = {
    'tool_call': 'border-blue-400 bg-blue-50',
    'thinking': 'border-purple-400 bg-purple-50',
    'analysis': 'border-green-400 bg-green-50',
    'finding': 'border-orange-400 bg-orange-50',
  }
  return classes[type] || 'border-gray-400 bg-gray-50'
}

const formatDuration = (ms) => {
  if (!ms) return ''
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

const clearInteractions = () => {
  interactions.value = []
}

const selectAllVulnTypes = () => {
  config.vulnTypes = vulnTypes.map(v => v.value)
}

const clearVulnTypes = () => {
  config.vulnTypes = []
}

const browsePath = () => {
  alert('请手动输入项目路径')
}

const resetConfig = () => {
  config.targetPath = ''
  config.languages = []
  config.vulnTypes = ['rce', 'command_injection', 'sql_injection']
  config.useLLM = true
  config.scanLogic = true
  config.useChainAnalysis = true
  config.reindex = false
  config.skipIndex = false
  config.maxIssues = 50
  config.maxChainDepth = 5
}

const startScan = async () => {
  if (!config.targetPath) {
    alert('请输入目标路径')
    return
  }

  isScanning.value = true
  logs.value = []
  interactions.value = []  // 清空交互日志
  addLog('开始扫描任务...', 'info')

  try {
    const result = await api.startScan({
      target_path: config.targetPath,
      languages: config.languages.length > 0 ? config.languages : null,
      vuln_types: config.vulnTypes.length > 0 ? config.vulnTypes : null,
      use_llm: config.useLLM,
      scan_logic: config.scanLogic,
      use_chain_analysis: config.useChainAnalysis,
      reindex: config.reindex,
      skip_index: config.skipIndex,
      max_issues: config.maxIssues,
      max_chain_depth: config.maxChainDepth,
    })

    if (result.success) {
      const scanId = result.data.scan_id
      addLog(`扫描任务已创建: ${scanId}`, 'success')

      currentScan.value = {
        scan_id: scanId,
        status: 'pending',
        progress: 0,
        current_step: '准备中...',
        findings: [],
        vuln_findings: [],
      }

      try {
        ws = api.createScanWebSocket(scanId)
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data)
          if (data.type === 'progress') {
            currentScan.value = { ...currentScan.value, ...data }
            if (data.log) {
              addLog(data.log, data.log_level || 'info')
            }
          } else if (data.type === 'interaction') {
            // 处理 LLM 交互日志
            handleInteraction(data.data)
          } else if (data.type === 'llm_stream') {
            // 处理 LLM 流式响应 - 实时显示 LLM 输出
            if (data.content) {
              // 将流式内容追加到当前分析日志
              addLog(data.content, 'info', true) // true = 追加模式
            }
          } else if (data.type === 'analysis_detail') {
            // 处理分析详情 - 显示分析进度细节
            if (data.data && data.data.message) {
              addLog(`[${data.detail_type}] ${data.data.message}`, 'info')
            }
          }
        }
        ws.onerror = () => {
          addLog('WebSocket 连接失败，切换到轮询模式', 'warning')
          startPolling(scanId)
        }
      } catch {
        startPolling(scanId)
      }
    }
  } catch (error) {
    addLog(`启动失败: ${error.message}`, 'error')
    console.error('Start scan failed:', error)
  } finally {
    isScanning.value = false
  }
}

const startPolling = (scanId) => {
  pollInterval = setInterval(async () => {
    try {
      const result = await api.getScanResult(scanId)
      if (result.success) {
        currentScan.value = result.data
        if (result.data.status === 'completed') {
          addLog('扫描完成！', 'success')
          clearInterval(pollInterval)
          pollInterval = null
          appStore.fetchScanHistory()
        } else if (result.data.status === 'failed') {
          addLog('扫描失败', 'error')
          clearInterval(pollInterval)
          pollInterval = null
        }
      }
    } catch (error) {
      console.error('Poll failed:', error)
    }
  }, 2000)
}

const cancelScan = () => {
  if (confirm('确定要取消当前扫描吗？')) {
    if (ws) ws.close()
    if (pollInterval) clearInterval(pollInterval)
    currentScan.value = null
    interactions.value = []  // 清空交互日志
    addLog('扫描已取消', 'warning')
  }
}

const viewResults = () => {
  if (currentScan.value) {
    router.push(`/results/${currentScan.value.scan_id}`)
  }
}

// 恢复正在进行的扫描状态
const restoreRunningScan = async () => {
  try {
    const result = await api.listScans()
    if (result.success && result.data.tasks) {
      // 查找正在运行的扫描任务（状态不是 completed 或 failed）
      const runningScan = result.data.tasks.find(
        task => task.status !== 'completed' && task.status !== 'failed'
      )

      if (runningScan) {
        addLog(`恢复扫描任务: ${runningScan.scan_id}`, 'info')

        // 获取完整的扫描状态
        const scanResult = await api.getScanResult(runningScan.scan_id)
        if (scanResult.success) {
          currentScan.value = {
            scan_id: runningScan.scan_id,
            status: scanResult.data.status,
            progress: scanResult.data.progress || 0,
            current_step: scanResult.data.current_step || '恢复中...',
            findings: scanResult.data.findings || [],
            vuln_findings: scanResult.data.vuln_findings || [],
            total_units: scanResult.data.total_units || 0,
          }

          // 如果扫描还在进行中，重新连接 WebSocket
          if (runningScan.status !== 'completed' && runningScan.status !== 'failed') {
            try {
              ws = api.createScanWebSocket(runningScan.scan_id)
              ws.onmessage = (event) => {
                const data = JSON.parse(event.data)
                if (data.type === 'progress') {
                  currentScan.value = { ...currentScan.value, ...data }
                  if (data.log) {
                    addLog(data.log, data.log_level || 'info')
                  }
                } else if (data.type === 'interaction') {
                  handleInteraction(data.data)
                } else if (data.type === 'llm_stream') {
                  if (data.content) {
                    addLog(data.content, 'info', true)
                  }
                } else if (data.type === 'analysis_detail') {
                  if (data.data && data.data.message) {
                    addLog(`[${data.detail_type}] ${data.data.message}`, 'info')
                  }
                }
              }
              ws.onerror = () => {
                addLog('WebSocket 重连失败，切换到轮询模式', 'warning')
                startPolling(runningScan.scan_id)
              }
              addLog('已重新连接 WebSocket', 'success')
            } catch {
              startPolling(runningScan.scan_id)
            }
          }
        }
      }
    }
  } catch (error) {
    console.error('恢复扫描状态失败:', error)
  }
}

onMounted(() => {
  // 页面加载时检查是否有正在进行的扫描
  restoreRunningScan()
})

onUnmounted(() => {
  if (ws) ws.close()
  if (pollInterval) clearInterval(pollInterval)
})
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

.lang-icon {
  @apply w-8 h-8 rounded-lg flex items-center justify-center text-white text-xs font-bold;
}

.vuln-chip {
  @apply flex items-center gap-2 px-3 py-1.5 rounded-lg cursor-pointer text-sm transition-all duration-200;
  background: rgba(255, 255, 255, 0.4);
  border: 1px solid transparent;
}

.vuln-chip:hover {
  background: rgba(255, 255, 255, 0.6);
}

.vuln-chip.active {
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.3);
  color: rgb(185, 28, 28);
}

.vuln-dot {
  @apply w-2 h-2 rounded-full;
}

.option-card {
  @apply flex items-start gap-3 p-4 rounded-xl cursor-pointer transition-all duration-200;
  background: rgba(255, 255, 255, 0.4);
}

.option-card:hover {
  background: rgba(255, 255, 255, 0.6);
}

.option-checkbox {
  @apply w-5 h-5 rounded-md flex items-center justify-center transition-all shrink-0 mt-0.5;
  background: rgba(255, 255, 255, 0.8);
  border: 2px solid rgba(0, 0, 0, 0.1);
}

.option-checkbox.checked {
  background: rgb(59, 130, 246);
  border-color: rgb(59, 130, 246);
  color: white;
}

.slide-enter-active,
.slide-leave-active {
  transition: all 0.3s ease;
}

.slide-enter-from,
.slide-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
</style>
