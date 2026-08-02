-- ═══════════════════════════════════════════════════════════════
-- RECTOR HUB — Supabase Database Schema
-- Run this script in your Supabase SQL Editor (https://supabase.com/dashboard/project/_/sql)
-- ═══════════════════════════════════════════════════════════════

-- 1. Create Products Table
CREATE TABLE IF NOT EXISTS public.products (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    price NUMERIC(12, 2) NOT NULL,
    old_price NUMERIC(12, 2),
    image TEXT NOT NULL,
    desc_text TEXT,
    stock INT DEFAULT 10,
    rating NUMERIC(3, 2) DEFAULT 4.8,
    is_featured BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 2. Create User Profiles Table (Linked to Supabase Auth)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(50),
    role VARCHAR(50) DEFAULT 'customer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 3. Create Orders Table
CREATE TABLE IF NOT EXISTS public.orders (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    customer_name VARCHAR(255) NOT NULL,
    customer_email VARCHAR(255) NOT NULL,
    customer_phone VARCHAR(50) NOT NULL,
    shipping_address TEXT NOT NULL,
    items JSONB NOT NULL,
    total_amount NUMERIC(12, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 4. Enable Row Level Security (RLS)
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;

-- 5. Products RLS Policies
CREATE POLICY "Public read products" ON public.products
    FOR SELECT USING (true);

CREATE POLICY "Admin write products" ON public.products
    FOR ALL USING (
        auth.jwt() ->> 'email' IN (SELECT email FROM public.profiles WHERE role = 'admin')
    );

-- 6. Profiles RLS Policies
CREATE POLICY "Users read own profile" ON public.profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users update own profile" ON public.profiles
    FOR UPDATE USING (auth.uid() = id);

-- 7. Orders RLS Policies
CREATE POLICY "Users read own orders" ON public.orders
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Public insert orders" ON public.orders
    FOR INSERT WITH CHECK (true);

-- 8. Seed Initial Products Data
INSERT INTO public.products (name, category, price, old_price, image, desc_text, is_featured) VALUES
('iPhone 13 Pro Max', 'phones', 450000.00, 480000.00, 'images/iphone_113-removebg-preview.png', '256GB, A15 chip, triple camera', true),
('iPhone 13 Pro', 'phones', 400000.00, 430000.00, 'images/iphone_113-removebg-preview.png', '256GB, A15 chip, triple camera', true),
('iPhone 13', 'phones', 350000.00, 380000.00, 'images/iphone_113-removebg-preview.png', '128GB, A15 chip, dual camera', true),
('iPhone 12 Pro Max', 'phones', 320000.00, 350000.00, 'images/iphone_113-removebg-preview.png', '128GB, A14 chip', false),
('iPhone 12', 'phones', 280000.00, 300000.00, 'images/iphone_113-removebg-preview.png', '128GB, A14 chip, dual camera', false),
('iPhone 11', 'phones', 220000.00, 240000.00, 'images/iphone_113-removebg-preview.png', '64GB, A13 chip, dual camera', false),
('iPhone XS Max', 'phones', 180000.00, 200000.00, 'images/xs.png', '64GB, A12 chip, dual camera', false),
('MacBook Pro 14 inch', 'laptops', 850000.00, 920000.00, 'images/hero img.png', 'M1 Pro, 16GB RAM, 512GB SSD', true),
('MacBook Air M2', 'laptops', 650000.00, 700000.00, 'images/hero img.png', 'M2 chip, 8GB RAM, 256GB SSD', true),
('Dell XPS 13', 'laptops', 550000.00, 600000.00, 'images/hero img.png', 'Intel i7, 16GB RAM, 512GB SSD', false),
('iPad Pro 12.9 inch', 'tablets', 550000.00, 600000.00, 'images/hero img.png', 'M1 chip, 128GB, WiFi', true),
('AirPods Pro', 'accessories', 120000.00, 140000.00, 'images/Airpods-removebg-preview.png', 'Active noise cancellation', true)
ON CONFLICT DO NOTHING;
