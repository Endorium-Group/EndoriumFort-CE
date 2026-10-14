import React, { useLayoutEffect, useRef } from 'react';

// Shows a long-lived DOM node (the xterm host owned by App) inside the page.
// The node is moved, not recreated, so the SSH terminal and its socket survive
// navigating between sections.
export default function TerminalSlot({ host, onAttach, className, style }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    const slot = ref.current;
    if (!slot || !host) return undefined;
    slot.appendChild(host);
    onAttach?.();
    return () => {
      if (host.parentNode === slot) slot.removeChild(host);
    };
  }, [host]);
  return <div ref={ref} className={className} style={style} />;
}
