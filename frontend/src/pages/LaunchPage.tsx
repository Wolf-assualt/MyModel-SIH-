import React from 'react';
import { motion } from 'framer-motion';
import { HeroSection } from '../components/launch/HeroSection';
import { ArtifactUploader } from '../components/launch/ArtifactUploader';
import { ValidationChecklist } from '../components/launch/ValidationChecklist';
import { LatencyHistogram } from '../components/launch/LatencyHistogram';

const sectionVariants = {
  hidden: { opacity: 0, y: 10 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.25, ease: 'easeOut' as const } },
};

export const LaunchPage: React.FC = () => {
  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={{ visible: { transition: { staggerChildren: 0.05 } } }}
      style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
    >
      <motion.section variants={sectionVariants}>
        <HeroSection />
      </motion.section>

      <motion.section variants={sectionVariants}>
        <LatencyHistogram />
      </motion.section>

      <motion.section variants={sectionVariants}>
        <div style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2
              style={{
                fontSize: '1.25rem',
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '0.04em',
                margin: 0,
              }}
              className="font-display"
            >
              Investigation Artifact Setup
            </h2>
            <p
              style={{
                fontSize: '0.8125rem',
                color: 'var(--text-secondary)',
                margin: 0,
              }}
            >
              Provide surveillance datasets, neural network weights, and inference outputs for validation.
            </p>
          </div>
        </div>

        <ArtifactUploader />
      </motion.section>

      <motion.section variants={sectionVariants}>
        <ValidationChecklist />
      </motion.section>
    </motion.div>
  );
};
