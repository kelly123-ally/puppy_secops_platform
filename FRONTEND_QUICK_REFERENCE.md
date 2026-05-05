# 前端优化快速参考指南

## 🎯 核心优化点

### 性能优化
```css
/* 启用硬件加速 */
.element {
  transform: translateZ(0);
  will-change: transform;
  backface-visibility: hidden;
}

/* 使用 CSS 变量 */
:root {
  --transition-fast: 0.15s;
  --transition-normal: 0.3s;
  --transition-slow: 0.5s;
}
```

```javascript
// 防抖函数
function debounce(func, wait) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

// 节流函数
function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// 使用 requestAnimationFrame
requestAnimationFrame(() => render(data));
```

### 通知系统
```javascript
// 显示通知
notifications.success('操作成功', 2000);
notifications.error('操作失败', 3000);
notifications.warning('警告信息', 2500);
```

### WebSocket 优化
```javascript
// 连接管理
const state = {
  isConnecting: false,
  reconnectAttempts: 0,
  maxReconnectAttempts: 5,
  reconnectDelay: 1000
};

// 指数退避重连
const delay = state.reconnectDelay * Math.pow(2, state.reconnectAttempts - 1);
```

## 🎨 样式指南

### 颜色系统
```css
--bg: #0b1020;           /* 背景色 */
--panel: rgba(16, 24, 48, 0.72);  /* 面板背景 */
--text: #eef3ff;         /* 主文本 */
--muted: #91a0c0;        /* 次要文本 */
--accent: #4da3ff;       /* 强调色 */
--accent-2: #78ffd6;     /* 辅助强调色 */
--danger: #ff6b7a;       /* 危险色 */
--warning: #ffcc66;      /* 警告色 */
--success: #4ce39a;      /* 成功色 */
```

### 动画效果
```css
/* 滑入动画 */
@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* 脉冲动画 */
@keyframes pulse {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.8;
    transform: scale(1.05);
  }
}

/* 旋转动画 */
@keyframes spin {
  to { transform: rotate(360deg); }
}
```

### 玻璃态效果
```css
.glass {
  background: var(--panel);
  border: 1px solid var(--border);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
  box-shadow: var(--shadow);
}
```

## 📱 响应式断点

```css
/* 中等屏幕 */
@media (max-width: 1320px) {
  .metric-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

/* 平板设备 */
@media (max-width: 980px) {
  .app-shell {
    grid-template-columns: 1fr;
  }
  .sidebar {
    display: none;
  }
}

/* 移动设备 */
@media (max-width: 640px) {
  .metric-grid {
    grid-template-columns: 1fr;
  }
}
```

## ♿ 可访问性

### ARIA 标签
```html
<!-- 导航 -->
<nav role="navigation" aria-label="主导航">
  <button aria-label="总体态势">总体态势</button>
</nav>

<!-- 动态内容 -->
<div id="status" aria-live="polite">连接中</div>

<!-- 表单 -->
<label for="username">用户名</label>
<input id="username" aria-required="true" />
```

### 键盘支持
```javascript
// Enter 键提交
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    form.requestSubmit();
  }
});
```

## 🔧 常用工具函数

### 文本更新动画
```javascript
function setTextWithAnimation(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  
  const oldValue = el.textContent;
  if (oldValue !== value.toString()) {
    el.classList.add('pulse');
    el.textContent = value;
    setTimeout(() => el.classList.remove('pulse'), 500);
  }
}
```

### HTML 转义
```javascript
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
```

### 时间格式化
```javascript
function formatTimestamp(timestamp) {
  const date = new Date(timestamp * 1000);
  return date.toLocaleString('zh-CN');
}
```

## 📊 图表配置

### Chart.js 通用配置
```javascript
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
        color: '#eef3ff'
      }
    },
    tooltip: {
      backgroundColor: 'rgba(16, 24, 48, 0.95)',
      titleColor: '#eef3ff',
      bodyColor: '#91a0c0',
      borderColor: 'rgba(77, 163, 255, 0.3)',
      borderWidth: 1,
      padding: 12,
      cornerRadius: 8
    }
  }
};
```

## 🚀 性能优化清单

### CSS 优化
- [x] 使用 `transform` 代替 `top/left`
- [x] 添加 `will-change` 提示浏览器
- [x] 启用硬件加速
- [x] 优化动画缓动函数
- [x] 使用 CSS 变量

### JavaScript 优化
- [x] 防抖高频事件
- [x] 节流渲染函数
- [x] 使用 `requestAnimationFrame`
- [x] 优化 WebSocket 连接
- [x] 添加错误处理

### 资源优化
- [x] 预加载关键资源
- [x] 内联关键 CSS
- [x] 添加加载动画
- [x] 优化图片加载

## 🐛 调试技巧

### 性能监控
```javascript
// 页面加载时间
window.addEventListener('load', () => {
  const timing = window.performance.timing;
  const loadTime = timing.loadEventEnd - timing.navigationStart;
  console.log(`Page load time: ${loadTime}ms`);
});

// FPS 监控
let lastTime = performance.now();
let frames = 0;
function measureFPS() {
  frames++;
  const currentTime = performance.now();
  if (currentTime >= lastTime + 1000) {
    const fps = Math.round((frames * 1000) / (currentTime - lastTime));
    console.log(`FPS: ${fps}`);
    frames = 0;
    lastTime = currentTime;
  }
  requestAnimationFrame(measureFPS);
}
measureFPS();
```

### 内存监控
```javascript
// 检查内存使用
if (performance.memory) {
  console.log('Used JS Heap:', 
    (performance.memory.usedJSHeapSize / 1048576).toFixed(2), 'MB');
  console.log('Total JS Heap:', 
    (performance.memory.totalJSHeapSize / 1048576).toFixed(2), 'MB');
}
```

## 📝 代码规范

### 命名约定
- **变量**：camelCase（例如：`userName`, `isConnected`）
- **常量**：UPPER_SNAKE_CASE（例如：`MAX_RETRIES`, `API_URL`）
- **类名**：PascalCase（例如：`SecurityDashboard`, `WebSocketManager`）
- **CSS 类**：kebab-case（例如：`metric-card`, `glass-panel`）

### 注释规范
```javascript
/**
 * 函数描述
 * 
 * @param {string} param1 - 参数1描述
 * @param {number} param2 - 参数2描述
 * @returns {boolean} 返回值描述
 */
function myFunction(param1, param2) {
  // 实现代码
}
```

## 🔍 常见问题

### Q: 动画卡顿怎么办？
A: 
1. 检查是否使用了 `transform` 而不是 `top/left`
2. 添加 `will-change` 属性
3. 使用 `requestAnimationFrame`
4. 减少 DOM 操作频率

### Q: WebSocket 频繁断开？
A: 
1. 检查心跳机制是否正常
2. 实现指数退避重连
3. 添加最大重连次数限制
4. 检查网络状态

### Q: 图表不显示？
A: 
1. 检查 Chart.js 是否加载
2. 确认 canvas 元素存在
3. 检查数据格式是否正确
4. 查看控制台错误信息

### Q: 移动端显示异常？
A: 
1. 检查 viewport meta 标签
2. 测试响应式断点
3. 检查触摸事件处理
4. 验证字体大小

## 📚 参考资源

- [MDN Web Docs](https://developer.mozilla.org/)
- [Can I Use](https://caniuse.com/)
- [Chart.js Documentation](https://www.chartjs.org/docs/)
- [Web.dev Performance](https://web.dev/performance/)
- [ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/)

---

**最后更新**：2026-05-05  
**版本**：v2.0
