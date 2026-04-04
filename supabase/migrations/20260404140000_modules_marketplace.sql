-- Module marketplace tables
CREATE TABLE IF NOT EXISTS modules (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT,
  long_description TEXT,
  author_name TEXT,
  author_email TEXT,
  author_url TEXT,
  homepage_url TEXT,
  git_url TEXT,
  logo_url TEXT,
  banner_url TEXT,
  screenshot_url TEXT,
  license TEXT DEFAULT 'MIT',
  pricing_type TEXT DEFAULT 'free' CHECK (pricing_type IN ('free', 'paid', 'freemium')),
  price_usd NUMERIC(10,2),
  category TEXT DEFAULT 'security',
  tags TEXT[] DEFAULT '{}',
  keywords TEXT,
  version TEXT DEFAULT '0.1.0',
  min_threatcrush_version TEXT DEFAULT '>=0.1.0',
  os_support TEXT[] DEFAULT '{linux}',
  capabilities TEXT[] DEFAULT '{}',
  downloads INTEGER DEFAULT 0,
  rating_avg NUMERIC(3,2) DEFAULT 0,
  rating_count INTEGER DEFAULT 0,
  verified BOOLEAN DEFAULT false,
  published BOOLEAN DEFAULT true,
  featured BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS module_versions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  module_id UUID REFERENCES modules(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  changelog TEXT,
  package_url TEXT,
  git_tag TEXT,
  min_threatcrush_version TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(module_id, version)
);

CREATE TABLE IF NOT EXISTS module_installs (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  module_id UUID REFERENCES modules(id) ON DELETE CASCADE,
  user_email TEXT,
  version TEXT,
  platform TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS module_reviews (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  module_id UUID REFERENCES modules(id) ON DELETE CASCADE,
  user_email TEXT NOT NULL,
  rating INTEGER CHECK (rating >= 1 AND rating <= 5),
  title TEXT,
  body TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(module_id, user_email)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_modules_slug ON modules(slug);
CREATE INDEX IF NOT EXISTS idx_modules_category ON modules(category);
CREATE INDEX IF NOT EXISTS idx_modules_pricing ON modules(pricing_type);
CREATE INDEX IF NOT EXISTS idx_modules_featured ON modules(featured) WHERE featured = true;
CREATE INDEX IF NOT EXISTS idx_module_versions_module ON module_versions(module_id);
CREATE INDEX IF NOT EXISTS idx_module_installs_module ON module_installs(module_id);
CREATE INDEX IF NOT EXISTS idx_module_reviews_module ON module_reviews(module_id);
