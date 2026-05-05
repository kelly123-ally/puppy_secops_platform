/**
 * Security Dashboard UI for PuppySecOps Platform
 * 
 * Provides real-time security monitoring interface with:
 * - WebSocket connections for real-time metrics and alerts
 * - Interactive charts for security metrics visualization
 * - Alert feed with severity indicators
 * - Time range selector for historical trends
 * - Filters for robot_id and event category
 * - Key rotation status display
 * 
 * Validates Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
 */

class SecurityDashboard {
    constructor() {
        // WebSocket connections
        this.metricsWs = null;
        this.alertsWs = null;
        
        // Connection state
        this.metricsConnected = false;
        this.alertsConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000; // Start with 1 second
        
        // Data storage
        this.currentMetrics = null;
        this.alerts = [];
        this.maxAlerts = 100; // Keep last 100 alerts
        
        // Charts
        this.metricsChart = null;
        this.attackTypesChart = null;
        
        // Filters
        this.timeRange = 'last_hour'; // last_hour, last_24h, last_7d, custom
        this.customStartTime = null;
        this.customEndTime = null;
        this.robotIdFilter = 'all';
        this.categoryFilter = 'all';
        
        // Initialize dashboard
        this.init();
    }
    
    /**
     * Initialize dashboard UI and connections
     */
    init() {
        console.log('[SecurityDashboard] Initializing...');
        
        // Attack type translations (English to Chinese)
        this.attackTypeTranslations = {
            'injection': '注入攻击',
            'replay': '重放攻击',
            'spoof': '伪造攻击',
            'invalid_completion': '无效完成',
            'revoked_sender': '已吊销发送者',
            'other': '其他攻击'
        };
        
        // Create dashboard UI elements
        this.createDashboardUI();
        
        // Initialize charts
        this.initCharts();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Connect to WebSocket endpoints
        this.connectMetricsWebSocket();
        this.connectAlertsWebSocket();
        
        console.log('[SecurityDashboard] Initialized');
    }
    
    /**
     * Create dashboard UI structure
     * 
     * Note: HTML template already provides the UI structure,
     * so this method just validates that required elements exist
     */
    createDashboardUI() {
        // Validate that required elements exist in the HTML template
        const requiredElements = [
            'metrics-status',
            'alerts-status',
            'time-range-select',
            'robot-filter',
            'category-filter',
            'metric-blocked-attacks',
            'metric-active-robots',
            'metric-revoked-certs',
            'metric-anomalies',
            'metric-auth-failures',
            'last-rotation',
            'next-rotation',
            'active-sessions',
            'metrics-chart',
            'attack-types-chart',
            'alert-feed'
        ];
        
        const missingElements = requiredElements.filter(id => !document.getElementById(id));
        
        if (missingElements.length > 0) {
            console.error('[SecurityDashboard] Missing required elements:', missingElements);
            throw new Error(`Missing required dashboard elements: ${missingElements.join(', ')}`);
        }
        
        console.log('[SecurityDashboard] All required UI elements found');
    }
    
    /**
     * Initialize Chart.js charts
     */
    initCharts() {
        // Check if Chart.js is loaded
        if (typeof Chart === 'undefined') {
            console.warn('[SecurityDashboard] Chart.js not loaded, loading from CDN...');
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
            script.onload = () => {
                console.log('[SecurityDashboard] Chart.js loaded');
                this.createCharts();
            };
            script.onerror = () => {
                console.error('[SecurityDashboard] Failed to load Chart.js');
                this.showError('无法加载图表库，请检查网络连接');
            };
            document.head.appendChild(script);
        } else {
            this.createCharts();
        }
    }
    
    /**
     * Show error message
     */
    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        document.querySelector('.content').prepend(errorDiv);
        
        setTimeout(() => errorDiv.remove(), 5000);
    }
    
    /**
     * Show success message
     */
    showSuccess(message) {
        const successDiv = document.createElement('div');
        successDiv.className = 'success-message';
        successDiv.textContent = message;
        document.querySelector('.content').prepend(successDiv);
        
        setTimeout(() => successDiv.remove(), 3000);
    }
    
    /**
     * Create Chart.js chart instances
     */
    createCharts() {
        // 通用图表配置
        const commonOptions = {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 750,
                easing: 'easeInOutQuart'
            },
            plugins: {
                legend: {
                    labels: {
                        font: {
                            family: "'Microsoft YaHei', 'SimHei', sans-serif",
                            size: 12
                        },
                        color: '#eef3ff',
                        padding: 15
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(16, 24, 48, 0.95)',
                    titleColor: '#eef3ff',
                    bodyColor: '#91a0c0',
                    borderColor: 'rgba(77, 163, 255, 0.3)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                    titleFont: {
                        size: 14,
                        weight: 'bold'
                    },
                    bodyFont: {
                        size: 13
                    }
                }
            }
        };
        
        // Metrics trend chart
        const metricsCtx = document.getElementById('metrics-chart');
        if (metricsCtx) {
            this.metricsChart = new Chart(metricsCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: '拦截攻击',
                            data: [],
                            borderColor: 'rgb(255, 99, 132)',
                            backgroundColor: 'rgba(255, 99, 132, 0.1)',
                            tension: 0.4,
                            fill: true,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        },
                        {
                            label: '活跃机器人',
                            data: [],
                            borderColor: 'rgb(54, 162, 235)',
                            backgroundColor: 'rgba(54, 162, 235, 0.1)',
                            tension: 0.4,
                            fill: true,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        },
                        {
                            label: '异常检测',
                            data: [],
                            borderColor: 'rgb(255, 206, 86)',
                            backgroundColor: 'rgba(255, 206, 86, 0.1)',
                            tension: 0.4,
                            fill: true,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        }
                    ]
                },
                options: {
                    ...commonOptions,
                    scales: {
                        x: {
                            type: 'time',
                            time: {
                                unit: 'minute',
                                displayFormats: {
                                    minute: 'HH:mm'
                                }
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)'
                            },
                            ticks: {
                                color: '#91a0c0',
                                font: {
                                    size: 11
                                }
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)'
                            },
                            ticks: {
                                color: '#91a0c0',
                                font: {
                                    size: 11
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // Attack types chart
        const attackTypesCtx = document.getElementById('attack-types-chart');
        if (attackTypesCtx) {
            this.attackTypesChart = new Chart(attackTypesCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: '拦截攻击（按类型）',
                        data: [],
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.8)',
                            'rgba(54, 162, 235, 0.8)',
                            'rgba(255, 206, 86, 0.8)',
                            'rgba(75, 192, 192, 0.8)',
                            'rgba(153, 102, 255, 0.8)'
                        ],
                        borderColor: [
                            'rgb(255, 99, 132)',
                            'rgb(54, 162, 235)',
                            'rgb(255, 206, 86)',
                            'rgb(75, 192, 192)',
                            'rgb(153, 102, 255)'
                        ],
                        borderWidth: 2,
                        borderRadius: 8
                    }]
                },
                options: {
                    ...commonOptions,
                    scales: {
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                color: '#91a0c0',
                                font: {
                                    family: "'Microsoft YaHei', 'SimHei', sans-serif",
                                    size: 11
                                }
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)'
                            },
                            ticks: {
                                color: '#91a0c0',
                                font: {
                                    size: 11
                                },
                                stepSize: 1
                            }
                        }
                    }
                }
            });
        }
    }
    
    /**
     * Setup event listeners for UI controls
     */
    setupEventListeners() {
        // Time range selector
        const timeRangeSelect = document.getElementById('time-range-select');
        if (timeRangeSelect) {
            timeRangeSelect.addEventListener('change', (e) => {
                this.timeRange = e.target.value;
                const customInputs = document.getElementById('custom-range-inputs');
                if (this.timeRange === 'custom') {
                    customInputs.style.display = 'block';
                } else {
                    customInputs.style.display = 'none';
                    this.loadHistoricalMetrics();
                }
            });
        }
        
        // Custom range apply button
        const applyCustomRange = document.getElementById('apply-custom-range');
        if (applyCustomRange) {
            applyCustomRange.addEventListener('click', () => {
                const startInput = document.getElementById('start-time');
                const endInput = document.getElementById('end-time');
                if (startInput.value && endInput.value) {
                    this.customStartTime = new Date(startInput.value).getTime() / 1000;
                    this.customEndTime = new Date(endInput.value).getTime() / 1000;
                    this.loadHistoricalMetrics();
                }
            });
        }
        
        // Robot filter
        const robotFilter = document.getElementById('robot-filter');
        if (robotFilter) {
            robotFilter.addEventListener('change', (e) => {
                this.robotIdFilter = e.target.value;
                this.filterAlerts();
            });
        }
        
        // Category filter
        const categoryFilter = document.getElementById('category-filter');
        if (categoryFilter) {
            categoryFilter.addEventListener('change', (e) => {
                this.categoryFilter = e.target.value;
                this.filterAlerts();
            });
        }
    }
    
    /**
     * Connect to metrics WebSocket endpoint
     */
    connectMetricsWebSocket() {
        if (this.metricsWs && this.metricsWs.readyState === WebSocket.OPEN) {
            console.log('[SecurityDashboard] Metrics WebSocket already connected');
            return;
        }
        
        console.log('[SecurityDashboard] Connecting to metrics WebSocket...');
        
        // Get session token from localStorage or cookie
        const token = this.getSessionToken();
        
        if (!token) {
            console.error('[SecurityDashboard] No session token found');
            this.showError('未找到会话令牌，请重新登录');
            return;
        }
        
        // Build WebSocket URL
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard/metrics?token=${token}`;
        
        try {
            this.metricsWs = new WebSocket(wsUrl);
            
            this.metricsWs.onopen = () => {
                console.log('[SecurityDashboard] Metrics WebSocket connected');
                this.metricsConnected = true;
                this.reconnectAttempts = 0;
                this.reconnectDelay = 1000;
                this.updateConnectionStatus('metrics', true);
                this.showSuccess('指标数据连接成功');
            };
            
            this.metricsWs.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMetricsMessage(data);
                } catch (error) {
                    console.error('[SecurityDashboard] Failed to parse metrics message:', error);
                }
            };
            
            this.metricsWs.onerror = (error) => {
                console.error('[SecurityDashboard] Metrics WebSocket error:', error);
                this.updateConnectionStatus('metrics', false);
            };
            
            this.metricsWs.onclose = (event) => {
                console.log('[SecurityDashboard] Metrics WebSocket closed:', event.code, event.reason);
                this.metricsConnected = false;
                this.updateConnectionStatus('metrics', false);
                this.reconnectMetricsWebSocket();
            };
        } catch (error) {
            console.error('[SecurityDashboard] Failed to connect metrics WebSocket:', error);
            this.showError('无法连接到指标数据服务');
            this.reconnectMetricsWebSocket();
        }
    }
    
    /**
     * Connect to alerts WebSocket endpoint
     */
    connectAlertsWebSocket() {
        console.log('[SecurityDashboard] Connecting to alerts WebSocket...');
        
        // Get session token from cookie
        const token = this.getSessionToken();
        
        // Build WebSocket URL
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard/alerts?token=${token}`;
        
        try {
            this.alertsWs = new WebSocket(wsUrl);
            
            this.alertsWs.onopen = () => {
                console.log('[SecurityDashboard] Alerts WebSocket connected');
                this.alertsConnected = true;
                this.reconnectAttempts = 0;
                this.reconnectDelay = 1000;
                this.updateConnectionStatus('alerts', true);
            };
            
            this.alertsWs.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleAlertsMessage(data);
            };
            
            this.alertsWs.onerror = (error) => {
                console.error('[SecurityDashboard] Alerts WebSocket error:', error);
                this.updateConnectionStatus('alerts', false);
            };
            
            this.alertsWs.onclose = () => {
                console.log('[SecurityDashboard] Alerts WebSocket closed');
                this.alertsConnected = false;
                this.updateConnectionStatus('alerts', false);
                this.reconnectAlertsWebSocket();
            };
        } catch (error) {
            console.error('[SecurityDashboard] Failed to connect alerts WebSocket:', error);
            this.reconnectAlertsWebSocket();
        }
    }
    
    /**
     * Reconnect metrics WebSocket with exponential backoff
     */
    reconnectMetricsWebSocket() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[SecurityDashboard] Max reconnect attempts reached for metrics WebSocket');
            return;
        }
        
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        
        console.log(`[SecurityDashboard] Reconnecting metrics WebSocket in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        setTimeout(() => {
            this.connectMetricsWebSocket();
        }, delay);
    }
    
    /**
     * Reconnect alerts WebSocket with exponential backoff
     */
    reconnectAlertsWebSocket() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[SecurityDashboard] Max reconnect attempts reached for alerts WebSocket');
            return;
        }
        
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        
        console.log(`[SecurityDashboard] Reconnecting alerts WebSocket in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        setTimeout(() => {
            this.connectAlertsWebSocket();
        }, delay);
    }
    
    /**
     * Handle metrics WebSocket message
     */
    handleMetricsMessage(data) {
        if (data.type === 'ping') {
            // Respond to ping
            if (this.metricsWs && this.metricsWs.readyState === WebSocket.OPEN) {
                this.metricsWs.send(JSON.stringify({ type: 'pong' }));
            }
            return;
        }
        
        if (data.type === 'metrics') {
            this.currentMetrics = data;
            this.updateMetricsDisplay(data);
        }
    }
    
    /**
     * Handle alerts WebSocket message
     */
    handleAlertsMessage(data) {
        if (data.type === 'ping') {
            // Respond to ping
            if (this.alertsWs && this.alertsWs.readyState === WebSocket.OPEN) {
                this.alertsWs.send(JSON.stringify({ type: 'pong' }));
            }
            return;
        }
        
        if (data.type === 'alert') {
            this.addAlert(data);
        }
    }
    
    /**
     * Update metrics display
     */
    updateMetricsDisplay(metrics) {
        // Update metric cards
        const blockedAttacks = Object.values(metrics.blocked_attacks_by_type || {}).reduce((a, b) => a + b, 0);
        this.updateMetricValue('metric-blocked-attacks', blockedAttacks);
        this.updateMetricValue('metric-active-robots', metrics.active_robots || 0);
        this.updateMetricValue('metric-revoked-certs', metrics.revoked_certificates || 0);
        this.updateMetricValue('metric-anomalies', metrics.anomaly_detections || 0);
        this.updateMetricValue('metric-auth-failures', metrics.authentication_failures || 0);
        
        // Update key rotation status
        const keyRotation = metrics.key_rotation_status || {};
        this.updateKeyRotationStatus(keyRotation);
        
        // Update attack types chart
        if (this.attackTypesChart && metrics.blocked_attacks_by_type) {
            const types = Object.keys(metrics.blocked_attacks_by_type);
            const counts = Object.values(metrics.blocked_attacks_by_type);
            
            // Translate attack types to Chinese
            const translatedTypes = types.map(type => {
                const translated = this.attackTypeTranslations[type] || type;
                console.log(`[SecurityDashboard] Translating "${type}" to "${translated}"`);
                return translated;
            });
            
            console.log('[SecurityDashboard] Original types:', types);
            console.log('[SecurityDashboard] Translated types:', translatedTypes);
            
            // Destroy and recreate chart to force label update
            this.attackTypesChart.destroy();
            
            const attackTypesCtx = document.getElementById('attack-types-chart');
            this.attackTypesChart = new Chart(attackTypesCtx, {
                type: 'bar',
                data: {
                    labels: translatedTypes,
                    datasets: [{
                        label: '拦截攻击（按类型）',
                        data: counts,
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 206, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)',
                            'rgba(153, 102, 255, 0.7)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                font: {
                                    family: "'Microsoft YaHei', 'SimHei', sans-serif"
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                font: {
                                    family: "'Microsoft YaHei', 'SimHei', sans-serif"
                                }
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                font: {
                                    family: "'Microsoft YaHei', 'SimHei', sans-serif"
                                }
                            }
                        }
                    }
                }
            });
            
            console.log('[SecurityDashboard] Chart recreated with labels:', this.attackTypesChart.data.labels);
        }
    }
    
    /**
     * Update a single metric value with animation
     */
    updateMetricValue(elementId, value) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const oldValue = parseInt(element.textContent) || 0;
        const newValue = parseInt(value) || 0;
        
        if (oldValue !== newValue) {
            // 添加更新动画
            element.classList.add('updating');
            
            // 数字动画效果
            const duration = 500;
            const steps = 20;
            const stepValue = (newValue - oldValue) / steps;
            const stepDuration = duration / steps;
            
            let currentStep = 0;
            const timer = setInterval(() => {
                currentStep++;
                if (currentStep >= steps) {
                    element.textContent = newValue;
                    clearInterval(timer);
                    element.classList.remove('updating');
                } else {
                    const currentValue = Math.round(oldValue + stepValue * currentStep);
                    element.textContent = currentValue;
                }
            }, stepDuration);
        }
    }
    
    /**
     * Update key rotation status display
     */
    updateKeyRotationStatus(status) {
        const lastRotation = document.getElementById('last-rotation');
        const nextRotation = document.getElementById('next-rotation');
        const activeSessions = document.getElementById('active-sessions');
        
        if (lastRotation) {
            lastRotation.textContent = status.last_rotation 
                ? this.formatTimestamp(status.last_rotation)
                : 'Never';
        }
        
        if (nextRotation) {
            nextRotation.textContent = status.next_rotation
                ? this.formatTimestamp(status.next_rotation)
                : 'N/A';
        }
        
        if (activeSessions) {
            activeSessions.textContent = status.active_sessions || 0;
        }
    }
    
    /**
     * Add alert to feed
     */
    addAlert(alert) {
        // Add to alerts array
        this.alerts.unshift(alert);
        
        // Keep only last N alerts
        if (this.alerts.length > this.maxAlerts) {
            this.alerts = this.alerts.slice(0, this.maxAlerts);
        }
        
        // Update alert feed display
        this.updateAlertFeed();
    }
    
    /**
     * Update alert feed display
     */
    updateAlertFeed() {
        const alertFeed = document.getElementById('alert-feed');
        if (!alertFeed) return;
        
        // Filter alerts based on current filters
        const filteredAlerts = this.getFilteredAlerts();
        
        // Clear feed
        alertFeed.innerHTML = '';
        
        // Add alerts
        filteredAlerts.forEach(alert => {
            const alertElement = this.createAlertElement(alert);
            alertFeed.appendChild(alertElement);
        });
        
        // Show message if no alerts
        if (filteredAlerts.length === 0) {
            alertFeed.innerHTML = '<div class="no-alerts">No alerts to display</div>';
        }
    }
    
    /**
     * Create alert DOM element
     */
    createAlertElement(alert) {
        const div = document.createElement('div');
        div.className = `alert-item alert-${alert.severity}`;
        
        // Severity indicator color
        const severityColors = {
            critical: '#dc3545',
            high: '#fd7e14',
            medium: '#ffc107',
            low: '#17a2b8'
        };
        
        div.innerHTML = `
            <div class="alert-header">
                <span class="alert-severity" style="background-color: ${severityColors[alert.severity] || '#6c757d'}">
                    ${alert.severity.toUpperCase()}
                </span>
                <span class="alert-timestamp">${this.formatTimestamp(alert.timestamp)}</span>
            </div>
            <div class="alert-title">${this.escapeHtml(alert.title || alert.category)}</div>
            <div class="alert-details">
                <div>Subject: ${this.escapeHtml(alert.subject)}</div>
                <div>Category: ${this.escapeHtml(alert.category)}</div>
            </div>
        `;
        
        return div;
    }
    
    /**
     * Get filtered alerts based on current filters
     */
    getFilteredAlerts() {
        return this.alerts.filter(alert => {
            // Robot ID filter
            if (this.robotIdFilter !== 'all' && alert.subject !== this.robotIdFilter) {
                return false;
            }
            
            // Category filter
            if (this.categoryFilter !== 'all' && alert.category !== this.categoryFilter) {
                return false;
            }
            
            return true;
        });
    }
    
    /**
     * Filter alerts based on current filter settings
     */
    filterAlerts() {
        this.updateAlertFeed();
    }
    
    /**
     * Load historical metrics from API
     */
    async loadHistoricalMetrics() {
        try {
            // Calculate time range
            const { startTime, endTime } = this.getTimeRange();
            
            // Fetch historical metrics
            const response = await fetch(
                `/api/dashboard/metrics/history?start_time=${startTime}&end_time=${endTime}`
            );
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.updateMetricsChart(data.metrics);
            
        } catch (error) {
            console.error('[SecurityDashboard] Failed to load historical metrics:', error);
        }
    }
    
    /**
     * Update metrics chart with historical data
     */
    updateMetricsChart(metrics) {
        if (!this.metricsChart) return;
        
        // Convert timestamps to Date objects
        const labels = metrics.timestamps.map(ts => new Date(ts * 1000));
        
        // Update chart data
        this.metricsChart.data.labels = labels;
        this.metricsChart.data.datasets[0].data = metrics.blocked_attacks;
        this.metricsChart.data.datasets[1].data = metrics.active_robots;
        this.metricsChart.data.datasets[2].data = metrics.anomaly_detections;
        
        this.metricsChart.update();
    }
    
    /**
     * Get time range based on current selection
     */
    getTimeRange() {
        const now = Date.now() / 1000;
        let startTime, endTime;
        
        switch (this.timeRange) {
            case 'last_hour':
                startTime = now - 3600;
                endTime = now;
                break;
            case 'last_24h':
                startTime = now - 86400;
                endTime = now;
                break;
            case 'last_7d':
                startTime = now - 604800;
                endTime = now;
                break;
            case 'custom':
                startTime = this.customStartTime || (now - 3600);
                endTime = this.customEndTime || now;
                break;
            default:
                startTime = now - 3600;
                endTime = now;
        }
        
        return { startTime, endTime };
    }
    
    /**
     * Update connection status indicator
     */
    updateConnectionStatus(type, connected) {
        const statusElement = document.getElementById(`${type}-status`);
        if (statusElement) {
            statusElement.style.color = connected ? '#28a745' : '#dc3545';
        }
    }
    
    /**
     * Get session token from localStorage or cookie
     */
    getSessionToken() {
        // Try localStorage first (used by main app)
        const localToken = localStorage.getItem('psp_token');
        if (localToken) {
            return localToken;
        }
        
        // Fall back to cookie
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'session_token' || name === 'psp_token') {
                return value;
            }
        }
        
        return '';
    }
    
    /**
     * Format Unix timestamp to human-readable format
     */
    formatTimestamp(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }
    
    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Cleanup and disconnect
     */
    destroy() {
        if (this.metricsWs) {
            this.metricsWs.close();
            this.metricsWs = null;
        }
        
        if (this.alertsWs) {
            this.alertsWs.close();
            this.alertsWs = null;
        }
        
        if (this.metricsChart) {
            this.metricsChart.destroy();
            this.metricsChart = null;
        }
        
        if (this.attackTypesChart) {
            this.attackTypesChart.destroy();
            this.attackTypesChart = null;
        }
    }
}

// Auto-initialize dashboard when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.securityDashboard = new SecurityDashboard();
    });
} else {
    window.securityDashboard = new SecurityDashboard();
}
