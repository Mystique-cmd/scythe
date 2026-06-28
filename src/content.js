// Content Script: Listens for user interactions on the inspected page and forwards them to background.js

function getElementIdentifier(element) {
  if (!element) return 'unknown element';
  
  const tagName = element.tagName.toLowerCase();
  
  if (element.id) {
    return `${tagName}#${element.id}`;
  }
  
  let descriptor = tagName;
  if (element.className && typeof element.className === 'string') {
    const classes = element.className.trim().split(/\s+/).join('.');
    if (classes) {
      descriptor += `.${classes}`;
    }
  }
  
  // Extract text or placeholder
  let text = '';
  if (element.textContent) {
    text = element.textContent.trim().substring(0, 30);
  } else if (element.value) {
    text = element.value.trim().substring(0, 30);
  } else if (element.placeholder) {
    text = element.placeholder.trim().substring(0, 30);
  }
  
  if (text) {
    descriptor += ` "${text}"`;
  }
  
  return descriptor;
}

// Track user actions and send to background page
function notifyUserAction(type, detail) {
  const message = {
    type: 'USER_ACTION',
    action: {
      type,
      detail,
      timestamp: Date.now(),
      url: window.location.href
    }
  };
  try {
    chrome.runtime.sendMessage(message);
  } catch (e) {
    // Ignore context invalidated errors when extension is reloaded
  }
}

// 1. Listen for clicks
document.addEventListener('click', (event) => {
  // We want to capture clicks on buttons, inputs, links, or elements with click handlers or cursor pointer
  // To avoid noise, let's focus on interactive elements or traverse up to find them
  let target = event.target;
  let interactive = null;
  
  while (target && target !== document.body) {
    const tag = target.tagName.toLowerCase();
    const isClickable = tag === 'button' || 
                        tag === 'a' || 
                        tag === 'input' || 
                        target.getAttribute('role') === 'button' ||
                        target.onclick ||
                        (window.getComputedStyle(target).cursor === 'pointer');
                        
    if (isClickable) {
      interactive = target;
      break;
    }
    target = target.parentElement;
  }
  
  // If we found an interactive element or if it's a direct target, report it
  const finalElement = interactive || event.target;
  const elementDesc = getElementIdentifier(finalElement);
  notifyUserAction('click', `Clicked on ${elementDesc}`);
}, true);

// 2. Listen for keydown (specifically Enter key on inputs/textarea)
document.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    const target = event.target;
    const tag = target.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea') {
      const elementDesc = getElementIdentifier(target);
      notifyUserAction('keypress', `Pressed Enter on ${elementDesc}`);
    }
  }
}, true);

// 3. Listen for form submit
document.addEventListener('submit', (event) => {
  const target = event.target;
  const elementDesc = getElementIdentifier(target);
  notifyUserAction('submit', `Submitted form ${elementDesc}`);
}, true);

// 4. Listen for navigation / history change
// Intercept history.pushState and history.replaceState
const originalPushState = history.pushState;
const originalReplaceState = history.replaceState;

history.pushState = function(...args) {
  originalPushState.apply(this, args);
  notifyUserAction('navigation', `Navigated to (pushState) ${args[2] || window.location.pathname}`);
};

history.replaceState = function(...args) {
  originalReplaceState.apply(this, args);
  notifyUserAction('navigation', `Navigated to (replaceState) ${args[2] || window.location.pathname}`);
};

// Listen for popstate (back/forward)
window.addEventListener('popstate', () => {
  notifyUserAction('navigation', `Navigated (popstate) to ${window.location.pathname}`);
});

// Listen for hashchange
window.addEventListener('hashchange', () => {
  notifyUserAction('navigation', `Navigated (hashchange) to ${window.location.hash}`);
});

console.log('[Workflow Detector] Content script initialized.');
