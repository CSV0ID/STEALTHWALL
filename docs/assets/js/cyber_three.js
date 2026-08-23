/* ==========================================================================
   STEALTHWALL — High-Performance Three.js 3D Cyber Defense Shield Engine
   ========================================================================== */

(function () {
  let scene, camera, renderer;
  let particleShield, coreIcosahedron, outerWireSphere, ringMesh;
  let laserBeams = [];
  let sparks = [];
  let mouseX = 0, mouseY = 0;
  let targetRotationX = 0, targetRotationY = 0;
  let isSimulatingAttack = false;

  function initThree() {
    const container = document.getElementById('three-hero-bg');
    if (!container || typeof THREE === 'undefined') return;

    // 1. Scene & Camera Setup for Dedicated Holographic Card
    scene = new THREE.Scene();
    const w = container.clientWidth || 400;
    const h = container.clientHeight || 340;
    camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
    camera.position.z = 35;

    // 2. WebGL Renderer
    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 3. Central Holographic Core (Icosahedron - High-Vibrancy Cyan & Emerald)
    const coreGeo = new THREE.IcosahedronGeometry(6.5, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4, // Neon Cyan
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    coreIcosahedron = new THREE.Mesh(coreGeo, coreMat);
    scene.add(coreIcosahedron);

    // Inner Glowing Core Node (Electric Emerald Core)
    const innerGeo = new THREE.IcosahedronGeometry(3.6, 2);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x10b981, // Electric Emerald
      wireframe: true,
      transparent: true,
      opacity: 0.95,
    });
    const innerCore = new THREE.Mesh(innerGeo, innerMat);
    coreIcosahedron.add(innerCore);

    // 4. Outer Defense Lattice Sphere (Represents Kernel iptables Gate - Cyber Blue)
    const outerGeo = new THREE.SphereGeometry(10.5, 16, 16);
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x3b82f6, // Electric Blue
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    });
    outerWireSphere = new THREE.Mesh(outerGeo, outerMat);
    scene.add(outerWireSphere);

    // 5. Equatorial Rotating Threat Intel Ring (Neon Purple Orbit)
    const ringGeo = new THREE.TorusGeometry(13.5, 0.15, 8, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0xa855f7, // Neon Purple
      transparent: true,
      opacity: 0.75,
    });
    ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 2.3;
    scene.add(ringMesh);

    // 6. Sliding-Window 14-Feature Node Cloud (Dual Emerald & Violet Particles)
    const particleCount = 260;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    const emeraldColor = new THREE.Color(0x34d399); // Soft Mint/Emerald
    const violetColor = new THREE.Color(0xa78bfa);  // Soft Violet

    for (let i = 0; i < particleCount; i++) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = 11 + Math.random() * 8.5;

      const x = r * Math.sin(phi) * Math.cos(theta);
      const y = r * Math.sin(phi) * Math.sin(theta);
      const z = r * Math.cos(phi);

      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      const c = (i % 2 === 0) ? emeraldColor : violetColor;
      colors[i * 3] = c.r;
      colors[i * 3 + 1] = c.g;
      colors[i * 3 + 2] = c.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.45,
      vertexColors: true,
      transparent: true,
      opacity: 0.55,
    });

    particleShield = new THREE.Points(geometry, particleMat);
    scene.add(particleShield);

    // 7. Event Listeners
    window.addEventListener('resize', onWindowResize);
    document.addEventListener('mousemove', onMouseMove);

    // 8. Start Animation Loop
    animate();
  }

  function onWindowResize() {
    const container = document.getElementById('three-hero-bg');
    if (!container || !renderer || !camera) return;
    const w = container.clientWidth || 400;
    const h = container.clientHeight || 340;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
  }

  function onMouseMove(event) {
    mouseX = (event.clientX / window.innerWidth) * 2 - 1;
    mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
  }

  function animate() {
    requestAnimationFrame(animate);

    const time = performance.now() * 0.001;

    // Smooth inertia camera tracking
    targetRotationX = mouseX * 0.4;
    targetRotationY = mouseY * 0.3;

    if (coreIcosahedron) {
      coreIcosahedron.rotation.x += 0.004;
      coreIcosahedron.rotation.y += 0.007;
    }

    if (outerWireSphere) {
      outerWireSphere.rotation.y -= 0.003;
      outerWireSphere.rotation.z += 0.002;
    }

    if (ringMesh) {
      ringMesh.rotation.z += 0.005;
    }

    if (particleShield) {
      particleShield.rotation.y += 0.002;
    }

    // Dynamic camera subtle pan
    if (camera) {
      camera.position.x += (targetRotationX * 6 - camera.position.x) * 0.05;
      camera.position.y += (targetRotationY * 5 - camera.position.y) * 0.05;
      camera.lookAt(0, 0, 0);
    }

    // Animate active attack laser beams & spark pulses
    for (let i = laserBeams.length - 1; i >= 0; i--) {
      const beam = laserBeams[i];
      beam.position.add(beam.velocity);
      beam.life -= 0.03;

      if (beam.position.length() < 10) {
        // Shield Deflection Impact!
        createSparks(beam.position, beam.color);
        scene.remove(beam.mesh);
        laserBeams.splice(i, 1);

        // Flash shield
        if (outerWireSphere) {
          outerWireSphere.material.color.setHex(beam.color);
          outerWireSphere.material.opacity = 0.9;
          setTimeout(() => {
            if (outerWireSphere) {
              outerWireSphere.material.color.setHex(0x1d4ed8);
              outerWireSphere.material.opacity = 0.25;
            }
          }, 350);
        }
      } else if (beam.life <= 0) {
        scene.remove(beam.mesh);
        laserBeams.splice(i, 1);
      }
    }

    // Animate spark bursts
    for (let i = sparks.length - 1; i >= 0; i--) {
      const s = sparks[i];
      s.position.add(s.velocity);
      s.life -= 0.04;
      s.mesh.scale.multiplyScalar(0.92);
      if (s.life <= 0) {
        scene.remove(s.mesh);
        sparks.splice(i, 1);
      }
    }

    if (renderer && scene && camera) {
      renderer.render(scene, camera);
    }
  }

  function createSparks(pos, colorHex) {
    const count = 16;
    for (let i = 0; i < count; i++) {
      const geo = new THREE.SphereGeometry(0.2, 4, 4);
      const mat = new THREE.MeshBasicMaterial({ color: colorHex, transparent: true, opacity: 0.9 });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      const vel = new THREE.Vector3(
        (Math.random() - 0.5) * 1.5,
        (Math.random() - 0.5) * 1.5,
        (Math.random() - 0.5) * 1.5
      );
      sparks.push({ mesh, velocity: vel, life: 1.0 });
      scene.add(mesh);
    }
  }

  // Triggered during interactive simulator attacks
  window.trigger3DShieldDeflection = function (attackType) {
    if (!scene) return;
    const isZday = attackType === 'zday_ssrf';
    const isBenign = attackType === 'benign';
    const colorHex = isZday ? 0xdb2777 : isBenign ? 0x10b981 : 0xef4444;

    // Launch 3 attack projectile beams from exterior space toward shield
    for (let i = 0; i < (isBenign ? 1 : 4); i++) {
      setTimeout(() => {
        const startRadius = 35;
        const angle = Math.random() * Math.PI * 2;
        const startPos = new THREE.Vector3(
          Math.cos(angle) * startRadius,
          (Math.random() - 0.5) * 20,
          Math.sin(angle) * startRadius
        );

        const geo = new THREE.SphereGeometry(isZday ? 0.6 : 0.45, 6, 6);
        const mat = new THREE.MeshBasicMaterial({ color: colorHex, transparent: true, opacity: 1.0 });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.copy(startPos);

        const dir = new THREE.Vector3(0, 0, 0).sub(startPos).normalize();
        const velocity = dir.multiplyScalar(isBenign ? 0.7 : 1.3);

        laserBeams.push({ mesh, velocity, life: 1.0, color: colorHex });
        scene.add(mesh);
      }, i * 120);
    }
  };

  // Auto-initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initThree);
  } else {
    initThree();
  }
})();
