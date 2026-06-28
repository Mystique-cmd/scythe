// DevTools Page: Creates the panel in developer tools

chrome.devtools.panels.create(
  "Workflow Detector", // Title shown in DevTools tab
  "icons/icon16.png",  // Path to icon (relative to extension root)
  "src/ui/panel.html", // Path to the panel page (relative to extension root)
  (panel) => {
    console.log('[Workflow Detector] DevTools panel created successfully.');
  }
);
