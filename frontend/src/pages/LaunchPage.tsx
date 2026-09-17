import React from 'react';
import { HeroSection } from '../components/launch/HeroSection';
import { ArtifactUploader } from '../components/launch/ArtifactUploader';
import { ValidationChecklist } from '../components/launch/ValidationChecklist';

export const LaunchPage: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <HeroSection />

      <section>
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
      </section>

      <ValidationChecklist />
    </div>
  );
};
