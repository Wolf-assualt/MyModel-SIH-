import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, Database, Cpu, Binary } from 'lucide-react';
import { Badge } from '../ui/Badge';

/** Animated counter: 0 → target over ~800ms with ease-out. */
const AnimatedCounter: React.FC<{ value: number; decimals?: number; suffix?: string }> = ({
  value,
  decimals = 0,
  suffix = '',
}) => {
  const [display, setDisplay] = useState(0);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    const start = performance.now();
    const duration = 800;
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(value * eased);
      if (t < 1) frameRef.current = requestAnimationFrame(tick);
    };
    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [value]);

  return (
    <span>
      {display.toFixed(decimals)}
      {suffix}
    </span>
  );
};

const HERO_METRICS: Array<{ label: string; value: number; decimals?: number; suffix: string }> = [
  { label: 'FORENSIC PIPELINE STAGES', value: 13, suffix: '' },
  { label: 'P95 VERIFY LATENCY', value: 29.28, decimals: 2, suffix: 'ms' },
  { label: 'AIR-GAP CAPABLE', value: 100, suffix: '%' },
];

interface HeroPill {
  id: string;
  icon: React.ReactNode;
  label: string;
}

const HERO_PILLS: HeroPill[] = [
  {
    id: 'art-dataset',
    icon: <Database size={15} style={{ color: 'var(--accent-text)' }} />,
    label: 'Dataset Poisoning & OOD',
  },
  {
    id: 'art-model',
    icon: <Cpu size={15} style={{ color: 'var(--success-text)' }} />,
    label: 'Weight Hash Verification',
  },
  {
    id: 'art-inference',
    icon: <Binary size={15} style={{ color: 'var(--warning-text)' }} />,
    label: 'Inference Anomaly Probe',
  },
  {
    id: 'art-manifest',
    icon: <ShieldCheck size={15} style={{ color: 'var(--accent-text)' }} />,
    label: 'Directed Evidence Graph',
  },
];

const scrollToArtifact = (artifactId: string) => {
  document.getElementById(`artifact-card-${artifactId}`)?.scrollIntoView({
    behavior: 'smooth',
    block: 'center',
  });
};

export const HeroSection: React.FC = () => {
  return (
    <section
      className="hero-fx"
      style={{
        padding: '2.5rem 0 2rem 0',
        textAlign: 'center',
        position: 'relative',
      }}
    >
      {/* Scanning-line sweep, every 6 seconds */}
      <div className="hero-scanline" aria-hidden="true" />

      <div style={{ position: 'relative' }}>
        <div style={{ display: 'inline-flex', marginBottom: '1rem' }}>
          <Badge variant="accent" size="md" pulse>
            FORENSIC INTEGRITY ASSURANCE PROTOCOL
          </Badge>
        </div>

        <h1
          style={{
            fontSize: '2.75rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            letterSpacing: '0.02em',
            lineHeight: 1.15,
            marginBottom: '1rem',
          }}
          className="font-display"
        >
          Establish Trust Before Inference.
        </h1>

        <p
          style={{
            fontSize: '1.0625rem',
            color: 'var(--text-secondary)',
            maxWidth: '780px',
            margin: '0 auto 1.75rem auto',
            lineHeight: 1.6,
          }}
        >
          Inspect computer-vision datasets, neural network weights, and inference outputs for
          clean-label poisoning, trigger backdoors, adversarial tampering, and evidence-chain inconsistencies
          before deployment to mission-critical systems.
        </p>

        {/* Animated benchmark metrics */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            flexWrap: 'wrap',
            gap: '2.25rem',
            marginBottom: '1.75rem',
          }}
        >
          {HERO_METRICS.map(metric => (
            <div key={metric.label} style={{ display: 'flex', flexDirection: 'column', gap: '0.125rem' }}>
              <span
                className="font-mono"
                style={{
                  fontSize: '1.25rem',
                  fontWeight: 700,
                  color: 'var(--accent-text)',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                <AnimatedCounter value={metric.value} decimals={metric.decimals ?? 0} suffix={metric.suffix} />
              </span>
              <span
                className="font-mono"
                style={{ fontSize: '0.625rem', color: 'var(--text-muted)', letterSpacing: '0.08em' }}
              >
                {metric.label}
              </span>
            </div>
          ))}
        </div>

        {/* Interactive capability pills — click scrolls to the matching artifact card */}
        <motion.div
          initial="hidden"
          animate="visible"
          variants={{ visible: { transition: { staggerChildren: 0.05 } } }}
          style={{
            display: 'flex',
            justifyContent: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          {HERO_PILLS.map(pill => (
            <motion.button
              key={pill.id}
              variants={{
                hidden: { opacity: 0, y: 8 },
                visible: { opacity: 1, y: 0, transition: { duration: 0.25, ease: 'easeOut' } },
              }}
              onClick={() => scrollToArtifact(pill.id)}
              className="hero-pill"
              aria-label={`Jump to ${pill.label} artifact`}
            >
              {pill.icon}
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
                {pill.label}
              </span>
            </motion.button>
          ))}
        </motion.div>
      </div>
    </section>
  );
};
