<template>
  <div class="space-y-8">
    <!-- 页面标题 -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white mb-2">系统设置</h1>
        <p class="text-white/60">配置 LLM 模型、嵌入模型和系统参数</p>
      </div>
      <button
        @click="saveSettings"
        :disabled="saving"
        class="btn-primary flex items-center gap-2"
      >
        <svg v-if="saving" class="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
        </svg>
        {{ saving ? '保存中...' : '保存设置' }}
      </button>
    </div>

    <!-- 设置面板容器 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- LLM 配置 -->
      <div class="glass-card p-6 space-y-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
          </div>
          <div>
            <h2 class="text-xl font-semibold text-gray-800">LLM 模型配置</h2>
            <p class="text-sm text-gray-500">配置用于代码审计的大语言模型</p>
          </div>
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">API Base URL</label>
            <input
              v-model="settings.llm.baseUrl"
              type="url"
              class="input-glass"
              placeholder="https://api.openai.com/v1"
            />
            <p class="text-xs text-gray-500 mt-1">支持 OpenAI 兼容格式的 API 地址</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">API Key</label>
            <div class="relative">
              <input
                v-model="settings.llm.apiKey"
                :type="showApiKey ? 'text' : 'password'"
                class="input-glass pr-10"
                placeholder="sk-..."
              />
              <button
                @click="showApiKey = !showApiKey"
                class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
              >
                <svg v-if="showApiKey" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                </svg>
                <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                </svg>
              </button>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">审计模型</label>
            <input
              v-model="settings.llm.model"
              type="text"
              class="input-glass"
              placeholder="gpt-4o / claude-3-opus / qwen-max"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Temperature</label>
            <div class="flex items-center gap-4">
              <input
                v-model.number="settings.llm.temperature"
                type="range"
                min="0"
                max="1"
                step="0.1"
                class="flex-1 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-blue-500"
              />
              <span class="text-sm text-gray-600 w-12 text-center glass-subtle px-2 py-1 rounded">
                {{ settings.llm.temperature }}
              </span>
            </div>
          </div>

          <div class="flex items-center justify-between pt-4 border-t border-gray-200/50">
            <span class="text-sm text-gray-700">连接测试</span>
            <button
              @click="testLlmConnection"
              :disabled="testingLlm"
              class="btn-secondary text-sm px-4 py-2"
            >
              <span v-if="testingLlm">测试中...</span>
              <span v-else-if="llmTestResult === 'success'" class="text-green-600">连接成功</span>
              <span v-else-if="llmTestResult === 'failed'" class="text-red-600">连接失败</span>
              <span v-else>测试连接</span>
            </button>
          </div>
        </div>
      </div>

      <!-- 嵌入模型配置 -->
      <div class="glass-card p-6 space-y-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-green-500 to-teal-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/>
            </svg>
          </div>
          <div>
            <h2 class="text-xl font-semibold text-gray-800">嵌入模型配置</h2>
            <p class="text-sm text-gray-500">配置用于代码向量化的嵌入模型</p>
          </div>
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">嵌入模型 API Base URL</label>
            <input
              v-model="settings.embedding.baseUrl"
              type="url"
              class="input-glass"
              placeholder="使用 LLM 相同地址则留空"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">嵌入模型</label>
            <input
              v-model="settings.embedding.model"
              type="text"
              class="input-glass"
              placeholder="text-embedding-3-small"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">向量维度</label>
            <select v-model="settings.embedding.dimensions" class="select-glass">
              <option value="256">256</option>
              <option value="512">512</option>
              <option value="768">768</option>
              <option value="1024">1024</option>
              <option value="1536">1536</option>
              <option value="3072">3072</option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">批处理大小</label>
            <input
              v-model.number="settings.embedding.batchSize"
              type="number"
              min="1"
              max="100"
              class="input-glass"
              placeholder="50"
            />
          </div>
        </div>
      </div>

      <!-- 向量存储配置 -->
      <div class="glass-card p-6 space-y-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500 to-red-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
            </svg>
          </div>
          <div>
            <h2 class="text-xl font-semibold text-gray-800">向量存储配置</h2>
            <p class="text-sm text-gray-500">配置代码索引的向量数据库</p>
          </div>
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">存储类型</label>
            <select v-model="settings.vectorStore.type" class="select-glass">
              <option value="qdrant">Qdrant</option>
              <option value="chroma">Chroma</option>
              <option value="memory">内存 (仅测试)</option>
            </select>
          </div>

          <div v-if="settings.vectorStore.type === 'qdrant'">
            <label class="block text-sm font-medium text-gray-700 mb-2">Qdrant URL</label>
            <input
              v-model="settings.vectorStore.url"
              type="url"
              class="input-glass"
              placeholder="http://localhost:6333"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">集合名称</label>
            <input
              v-model="settings.vectorStore.collection"
              type="text"
              class="input-glass"
              placeholder="code_audit"
            />
          </div>

          <div class="flex items-center justify-between pt-4 border-t border-gray-200/50">
            <div class="text-sm text-gray-600">
              <span v-if="cacheStats">
                缓存: {{ cacheStats.total_entries }} 条目, {{ cacheStats.cache_size_mb }} MB
              </span>
            </div>
            <button
              @click="clearCache"
              class="btn-secondary text-sm px-4 py-2 text-red-600"
            >
              清空缓存
            </button>
          </div>
        </div>
      </div>

      <!-- 扫描配置 -->
      <div class="glass-card p-6 space-y-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
          </div>
          <div>
            <h2 class="text-xl font-semibold text-gray-800">扫描配置</h2>
            <p class="text-sm text-gray-500">配置代码扫描的默认参数</p>
          </div>
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">最大并发数</label>
            <input
              v-model.number="settings.scan.maxConcurrent"
              type="number"
              min="1"
              max="10"
              class="input-glass"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">最大 Token 限制</label>
            <input
              v-model.number="settings.scan.maxTokens"
              type="number"
              min="1000"
              max="128000"
              step="1000"
              class="input-glass"
            />
          </div>

          <div class="flex items-center justify-between">
            <div>
              <span class="text-sm font-medium text-gray-700">启用高危漏洞增强检测</span>
              <p class="text-xs text-gray-500">包括 RCE、文件操作、反序列化等</p>
            </div>
            <label class="toggle-switch">
              <input type="checkbox" v-model="settings.scan.enhancedHighRisk">
              <span class="toggle-slider"></span>
            </label>
          </div>

          <div class="flex items-center justify-between">
            <div>
              <span class="text-sm font-medium text-gray-700">启用污点分析</span>
              <p class="text-xs text-gray-500">追踪 source 到 sink 的数据流</p>
            </div>
            <label class="toggle-switch">
              <input type="checkbox" v-model="settings.scan.enableTaintAnalysis">
              <span class="toggle-slider"></span>
            </label>
          </div>

          <div class="flex items-center justify-between">
            <div>
              <span class="text-sm font-medium text-gray-700">启用业务逻辑漏洞扫描</span>
              <p class="text-xs text-gray-500">检测认证绕过、越权等逻辑问题</p>
            </div>
            <label class="toggle-switch">
              <input type="checkbox" v-model="settings.scan.enableLogicScan">
              <span class="toggle-slider"></span>
            </label>
          </div>
        </div>
      </div>
    </div>

    <!-- 高危检测规则配置 -->
    <div class="glass-card p-6">
      <div class="flex items-center gap-3 mb-6">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-orange-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        </div>
        <div>
          <h2 class="text-xl font-semibold text-gray-800">高危漏洞检测增强</h2>
          <p class="text-sm text-gray-500">配置静态分析 + LLM 协作的高危漏洞检测流水线</p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- RCE 检测 -->
        <div
          class="selectable-card"
          :class="{ selected: settings.highRisk.rce }"
          @click="settings.highRisk.rce = !settings.highRisk.rce"
        >
          <div class="flex items-center gap-3 mb-2">
            <div class="w-8 h-8 rounded-lg bg-red-100 flex items-center justify-center">
              <svg class="w-4 h-4 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
              </svg>
            </div>
            <span class="font-medium text-gray-800">RCE 检测</span>
          </div>
          <p class="text-xs text-gray-500">命令执行、代码执行漏洞</p>
        </div>

        <!-- 文件操作 -->
        <div
          class="selectable-card"
          :class="{ selected: settings.highRisk.fileOps }"
          @click="settings.highRisk.fileOps = !settings.highRisk.fileOps"
        >
          <div class="flex items-center gap-3 mb-2">
            <div class="w-8 h-8 rounded-lg bg-orange-100 flex items-center justify-center">
              <svg class="w-4 h-4 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
              </svg>
            </div>
            <span class="font-medium text-gray-800">文件操作</span>
          </div>
          <p class="text-xs text-gray-500">任意文件读取/写入/路径穿越</p>
        </div>

        <!-- 反序列化 -->
        <div
          class="selectable-card"
          :class="{ selected: settings.highRisk.deserialization }"
          @click="settings.highRisk.deserialization = !settings.highRisk.deserialization"
        >
          <div class="flex items-center gap-3 mb-2">
            <div class="w-8 h-8 rounded-lg bg-purple-100 flex items-center justify-center">
              <svg class="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
              </svg>
            </div>
            <span class="font-medium text-gray-800">反序列化</span>
          </div>
          <p class="text-xs text-gray-500">不安全的反序列化操作</p>
        </div>

        <!-- SSTI -->
        <div
          class="selectable-card"
          :class="{ selected: settings.highRisk.ssti }"
          @click="settings.highRisk.ssti = !settings.highRisk.ssti"
        >
          <div class="flex items-center gap-3 mb-2">
            <div class="w-8 h-8 rounded-lg bg-pink-100 flex items-center justify-center">
              <svg class="w-4 h-4 text-pink-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
              </svg>
            </div>
            <span class="font-medium text-gray-800">模板注入</span>
          </div>
          <p class="text-xs text-gray-500">SSTI 服务端模板注入</p>
        </div>
      </div>

      <div class="mt-6 p-4 glass-blue rounded-xl">
        <div class="flex items-start gap-3">
          <svg class="w-5 h-5 text-blue-600 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <div class="text-sm text-gray-700">
            <p class="font-medium mb-1">高危检测流水线说明</p>
            <p class="text-gray-600">
              启用后，系统将使用静态分析精准定位危险调用，再由 LLM 进行逻辑层和可利用性的复核。
              只有当静态分析和 LLM 都认为高危且置信度较高时，才标记为"高优先级告警"。
            </p>
          </div>
        </div>
      </div>
    </div>

    <!-- 扫描模式选择 -->
    <div class="glass-card p-6">
      <div class="flex items-center gap-3 mb-6">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div>
          <h2 class="text-xl font-semibold text-gray-800">扫描模式</h2>
          <p class="text-sm text-gray-500">选择适合您需求的扫描策略</p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <!-- 快速规则模式 -->
        <div
          class="scan-mode-card"
          :class="{ active: settings.scanMode === 'fast-rule' }"
          @click="settings.scanMode = 'fast-rule'"
        >
          <div class="flex items-center gap-3 mb-3">
            <div class="w-10 h-10 rounded-xl bg-green-100 flex items-center justify-center">
              <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
              </svg>
            </div>
            <div>
              <h3 class="font-semibold text-gray-800">快速规则</h3>
              <span class="text-xs px-2 py-0.5 bg-green-100 text-green-700 rounded-full">推荐日常使用</span>
            </div>
          </div>
          <p class="text-sm text-gray-600 mb-3">仅使用静态规则匹配，不调用 LLM。速度最快，成本为零。</p>
          <div class="flex items-center gap-4 text-xs text-gray-500">
            <span class="flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              ~1-5 分钟
            </span>
            <span class="flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              $0
            </span>
          </div>
        </div>

        <!-- LLM 深度模式 -->
        <div
          class="scan-mode-card"
          :class="{ active: settings.scanMode === 'llm-deep' }"
          @click="settings.scanMode = 'llm-deep'"
        >
          <div class="flex items-center gap-3 mb-3">
            <div class="w-10 h-10 rounded-xl bg-blue-100 flex items-center justify-center">
              <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
              </svg>
            </div>
            <div>
              <h3 class="font-semibold text-gray-800">LLM 深度</h3>
              <span class="text-xs px-2 py-0.5 bg-blue-100 text-blue-700 rounded-full">平衡推荐</span>
            </div>
          </div>
          <p class="text-sm text-gray-600 mb-3">规则初筛 + LLM 深度分析高危候选。平衡速度和准确率。</p>
          <div class="flex items-center gap-4 text-xs text-gray-500">
            <span class="flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              ~10-30 分钟
            </span>
            <span class="flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              ~$0.5-2
            </span>
          </div>
        </div>

        <!-- 全量分析模式 -->
        <div
          class="scan-mode-card"
          :class="{ active: settings.scanMode === 'full' }"
          @click="settings.scanMode = 'full'"
        >
          <div class="flex items-center gap-3 mb-3">
            <div class="w-10 h-10 rounded-xl bg-purple-100 flex items-center justify-center">
              <svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>
            <div>
              <h3 class="font-semibold text-gray-800">全量分析</h3>
              <span class="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded-full">最全面</span>
            </div>
          </div>
          <p class="text-sm text-gray-600 mb-3">所有代码单元都经过 LLM 分析。最准确但成本最高。</p>
          <div class="flex items-center gap-4 text-xs text-gray-500">
            <span class="flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              ~1-3 小时
            </span>
            <span class="flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              ~$5-20
            </span>
          </div>
        </div>
      </div>

      <!-- 成本估算面板 -->
      <div class="mt-6 p-4 bg-gradient-to-r from-gray-50 to-gray-100/50 rounded-xl border border-gray-200/50">
        <div class="flex items-center justify-between mb-4">
          <h4 class="font-medium text-gray-800">本次扫描成本估算</h4>
          <button
            @click="estimateCost"
            :disabled="estimatingCost"
            class="btn-secondary text-sm px-3 py-1.5"
          >
            {{ estimatingCost ? '计算中...' : '重新估算' }}
          </button>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-4 gap-4" v-if="costEstimate">
          <div class="text-center p-3 glass-subtle rounded-lg">
            <div class="text-2xl font-bold text-gray-800">{{ costEstimate.files }}</div>
            <div class="text-xs text-gray-500">文件数</div>
          </div>
          <div class="text-center p-3 glass-subtle rounded-lg">
            <div class="text-2xl font-bold text-gray-800">{{ costEstimate.units }}</div>
            <div class="text-xs text-gray-500">代码单元</div>
          </div>
          <div class="text-center p-3 glass-subtle rounded-lg">
            <div class="text-2xl font-bold text-blue-600">{{ costEstimate.llmCalls }}</div>
            <div class="text-xs text-gray-500">预计 LLM 调用</div>
          </div>
          <div class="text-center p-3 glass-subtle rounded-lg">
            <div class="text-2xl font-bold text-green-600">${{ costEstimate.estimatedCost }}</div>
            <div class="text-xs text-gray-500">预计成本</div>
          </div>
        </div>
        <div v-else class="text-center py-6 text-gray-500">
          <p>配置项目路径后可估算扫描成本</p>
        </div>
      </div>
    </div>

    <!-- 配置测试 -->
    <div class="glass-card p-6">
      <div class="flex items-center gap-3 mb-6">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-green-600 flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
        </div>
        <div>
          <h2 class="text-xl font-semibold text-gray-800">配置验证</h2>
          <p class="text-sm text-gray-500">测试当前配置是否正常工作</p>
        </div>
      </div>

      <div class="space-y-4">
        <!-- 测试项目列表 -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            @click="runConfigTest('connection')"
            :disabled="configTestRunning"
            class="test-button"
            :class="{ 'test-success': configTestResults.connection === 'success', 'test-failed': configTestResults.connection === 'failed' }"
          >
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center">
                <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/>
                </svg>
              </div>
              <div class="text-left">
                <div class="font-medium text-gray-800">API 连接</div>
                <div class="text-xs text-gray-500">测试 LLM 和嵌入模型连接</div>
              </div>
            </div>
            <div v-if="configTestResults.connection" class="mt-2">
              <span v-if="configTestResults.connection === 'success'" class="text-xs text-green-600">通过</span>
              <span v-else-if="configTestResults.connection === 'failed'" class="text-xs text-red-600">失败</span>
              <span v-else class="text-xs text-gray-500">测试中...</span>
            </div>
          </button>

          <button
            @click="runConfigTest('rules')"
            :disabled="configTestRunning"
            class="test-button"
            :class="{ 'test-success': configTestResults.rules === 'success', 'test-failed': configTestResults.rules === 'failed' }"
          >
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-orange-100 flex items-center justify-center">
                <svg class="w-4 h-4 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/>
                </svg>
              </div>
              <div class="text-left">
                <div class="font-medium text-gray-800">规则加载</div>
                <div class="text-xs text-gray-500">验证安全规则配置</div>
              </div>
            </div>
            <div v-if="configTestResults.rules" class="mt-2">
              <span v-if="configTestResults.rules === 'success'" class="text-xs text-green-600">{{ rulesCount }} 条规则</span>
              <span v-else-if="configTestResults.rules === 'failed'" class="text-xs text-red-600">加载失败</span>
              <span v-else class="text-xs text-gray-500">测试中...</span>
            </div>
          </button>

          <button
            @click="runConfigTest('demo')"
            :disabled="configTestRunning"
            class="test-button"
            :class="{ 'test-success': configTestResults.demo === 'success', 'test-failed': configTestResults.demo === 'failed' }"
          >
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-purple-100 flex items-center justify-center">
                <svg class="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
              </div>
              <div class="text-left">
                <div class="font-medium text-gray-800">Demo 扫描</div>
                <div class="text-xs text-gray-500">运行示例代码分析</div>
              </div>
            </div>
            <div v-if="configTestResults.demo" class="mt-2">
              <span v-if="configTestResults.demo === 'success'" class="text-xs text-green-600">分析正常</span>
              <span v-else-if="configTestResults.demo === 'failed'" class="text-xs text-red-600">分析失败</span>
              <span v-else class="text-xs text-gray-500">测试中...</span>
            </div>
          </button>
        </div>

        <!-- 一键测试按钮 -->
        <div class="flex items-center justify-between pt-4 border-t border-gray-200/50">
          <div class="text-sm text-gray-600">
            <span v-if="allTestsPassed" class="text-green-600 flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              所有测试通过，配置正常
            </span>
            <span v-else-if="anyTestFailed" class="text-red-600 flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
              部分测试失败，请检查配置
            </span>
            <span v-else>点击右侧按钮开始验证配置</span>
          </div>
          <button
            @click="runAllTests"
            :disabled="configTestRunning"
            class="btn-primary"
          >
            <svg v-if="configTestRunning" class="w-5 h-5 spinner mr-2" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            {{ configTestRunning ? '测试中...' : '一键测试配置' }}
          </button>
        </div>
      </div>
    </div>

    <!-- 保存提示 -->
    <transition name="slide">
      <div
        v-if="showSaveSuccess"
        class="fixed bottom-6 right-6 glass-elevated p-4 flex items-center gap-3"
      >
        <div class="w-10 h-10 rounded-full bg-green-100 flex items-center justify-center">
          <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <div>
          <p class="font-medium text-gray-800">设置已保存</p>
          <p class="text-sm text-gray-500">配置已成功更新</p>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useAppStore } from '../stores/app'

const appStore = useAppStore()

const settings = reactive({
  llm: {
    baseUrl: 'https://api.openai.com/v1',
    apiKey: '',
    model: 'gpt-4o',
    temperature: 0.1
  },
  embedding: {
    baseUrl: '',
    model: 'text-embedding-3-small',
    dimensions: 1536,
    batchSize: 50
  },
  vectorStore: {
    type: 'qdrant',
    url: 'http://localhost:6333',
    collection: 'code_audit'
  },
  scan: {
    maxConcurrent: 3,
    maxTokens: 16000,
    enhancedHighRisk: true,
    enableTaintAnalysis: true,
    enableLogicScan: true
  },
  highRisk: {
    rce: true,
    fileOps: true,
    deserialization: true,
    ssti: true
  },
  // 新增：扫描模式
  scanMode: 'llm-deep'  // 'fast-rule' | 'llm-deep' | 'full'
})

const showApiKey = ref(false)
const saving = ref(false)
const showSaveSuccess = ref(false)
const testingLlm = ref(false)
const llmTestResult = ref(null)
const cacheStats = ref(null)

// 成本估算
const estimatingCost = ref(false)
const costEstimate = ref(null)

// 配置测试
const configTestRunning = ref(false)
const configTestResults = reactive({
  connection: null,
  rules: null,
  demo: null
})
const rulesCount = ref(0)

// 计算属性
const allTestsPassed = computed(() => {
  return configTestResults.connection === 'success' &&
         configTestResults.rules === 'success' &&
         configTestResults.demo === 'success'
})

const anyTestFailed = computed(() => {
  return configTestResults.connection === 'failed' ||
         configTestResults.rules === 'failed' ||
         configTestResults.demo === 'failed'
})

const saveSettings = async () => {
  saving.value = true
  try {
    // 模拟保存
    await new Promise(resolve => setTimeout(resolve, 1000))

    // 存储到本地
    localStorage.setItem('auditSettings', JSON.stringify(settings))

    showSaveSuccess.value = true
    setTimeout(() => {
      showSaveSuccess.value = false
    }, 3000)
  } finally {
    saving.value = false
  }
}

const testLlmConnection = async () => {
  testingLlm.value = true
  llmTestResult.value = null
  try {
    // 模拟测试连接
    await new Promise(resolve => setTimeout(resolve, 1500))
    llmTestResult.value = 'success'
  } catch {
    llmTestResult.value = 'failed'
  } finally {
    testingLlm.value = false
  }
}

const clearCache = async () => {
  if (confirm('确定要清空嵌入缓存吗？这将需要重新计算所有代码的向量。')) {
    // 清空缓存逻辑
    cacheStats.value = { total_entries: 0, cache_size_mb: 0 }
  }
}

// 成本估算
const estimateCost = async () => {
  estimatingCost.value = true
  try {
    // 模拟成本估算 - 实际应调用后端 API
    await new Promise(resolve => setTimeout(resolve, 1000))

    // 根据扫描模式计算预估
    const baseFiles = 150
    const baseUnits = 1200

    let llmCalls = 0
    let cost = 0

    switch (settings.scanMode) {
      case 'fast-rule':
        llmCalls = 0
        cost = 0
        break
      case 'llm-deep':
        llmCalls = Math.floor(baseUnits * 0.15) // 约15%需要LLM分析
        cost = llmCalls * 0.02
        break
      case 'full':
        llmCalls = baseUnits
        cost = llmCalls * 0.02
        break
    }

    costEstimate.value = {
      files: baseFiles,
      units: baseUnits,
      llmCalls,
      estimatedCost: cost.toFixed(2)
    }
  } finally {
    estimatingCost.value = false
  }
}

// 配置测试
const runConfigTest = async (testType) => {
  configTestRunning.value = true
  configTestResults[testType] = 'running'

  try {
    await new Promise(resolve => setTimeout(resolve, 1500))

    switch (testType) {
      case 'connection':
        // 测试 API 连接
        if (settings.llm.apiKey && settings.llm.baseUrl) {
          configTestResults.connection = 'success'
        } else {
          configTestResults.connection = 'failed'
        }
        break

      case 'rules':
        // 测试规则加载
        rulesCount.value = 47 // 模拟规则数量
        configTestResults.rules = 'success'
        break

      case 'demo':
        // 运行示例扫描
        if (configTestResults.connection === 'success') {
          configTestResults.demo = 'success'
        } else {
          configTestResults.demo = 'failed'
        }
        break
    }
  } catch {
    configTestResults[testType] = 'failed'
  } finally {
    configTestRunning.value = false
  }
}

const runAllTests = async () => {
  configTestRunning.value = true

  // 重置状态
  configTestResults.connection = null
  configTestResults.rules = null
  configTestResults.demo = null

  // 顺序执行测试
  await runConfigTest('connection')
  await runConfigTest('rules')
  await runConfigTest('demo')

  configTestRunning.value = false
}

onMounted(() => {
  // 从本地存储加载设置
  const saved = localStorage.getItem('auditSettings')
  if (saved) {
    try {
      const parsed = JSON.parse(saved)
      Object.assign(settings, parsed)
    } catch (e) {
      console.error('Failed to load settings:', e)
    }
  }

  // 模拟缓存统计
  cacheStats.value = {
    total_entries: 1234,
    cache_size_mb: 45.6
  }
})
</script>
