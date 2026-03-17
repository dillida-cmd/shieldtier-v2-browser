import { useRef, useEffect, useState, useCallback } from 'react';

/**
 * Returns the previous value of a state variable.
 * Useful for detecting changes to trigger animations.
 */
export function usePrevious<T>(value: T): T | undefined {
  const ref = useRef<T | undefined>(undefined);
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

/**
 * Returns true for `duration` ms after `value` changes.
 * Use to add a temporary animation class when a value updates.
 *
 * @example
 * const popping = useValueChanged(badgeCount, 300);
 * <span className={popping ? 'badge-pop' : ''}>
 */
export function useValueChanged(value: number | string, duration = 300): boolean {
  const [changed, setChanged] = useState(false);
  const prev = usePrevious(value);

  useEffect(() => {
    if (prev !== undefined && prev !== value) {
      setChanged(true);
      const timer = setTimeout(() => setChanged(false), duration);
      return () => clearTimeout(timer);
    }
  }, [value, prev, duration]);

  return changed;
}

/**
 * Animates a number from 0 to `target` over `duration` ms using requestAnimationFrame.
 * Returns the current animated value.
 *
 * @example
 * const animatedScore = useAnimatedNumber(score, 1000);
 * <span>{Math.round(animatedScore)}</span>
 */
export function useAnimatedNumber(target: number, duration = 1000): number {
  const [current, setCurrent] = useState(0);
  const frameRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    const start = performance.now();
    const from = current;

    const animate = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(from + (target - from) * eased);

      if (progress < 1) {
        frameRef.current = requestAnimationFrame(animate);
      }
    };

    frameRef.current = requestAnimationFrame(animate);

    return () => {
      if (frameRef.current !== undefined) {
        cancelAnimationFrame(frameRef.current);
      }
    };
  }, [target, duration]);

  return current;
}

/**
 * Returns a stable callback that triggers a CSS animation on an element.
 * Removes and re-adds the class to restart the animation.
 */
export function useTriggerAnimation(className: string) {
  return useCallback((el: HTMLElement | null) => {
    if (!el) return;
    el.classList.remove(className);
    // Force reflow to restart animation
    void el.offsetWidth;
    el.classList.add(className);
  }, [className]);
}
