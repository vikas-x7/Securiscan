"use client";

import { useState } from "react";
import Script from "next/script";
import Navbar from "@/client/home/components/Navbar";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { FiCheckCircle } from "react-icons/fi";

const plans = [
  {
    name: "BASIC",
    price: 1,
    description: "Perfect for hobbyists and small projects.",
    features: ["5 API scans per month", "Basic PDF reporting", "Email support"],
  },
  {
    name: "PRO",
    price: 2,
    description: "Ideal for growing teams and professionals.",
    features: [
      "Unlimited API scans",
      "Advanced reporting (PDF, JSON)",
      "Priority 24/7 support",
      "CI/CD Integration",
    ],
    popular: true,
  },
  {
    name: "ENTERPRISE",
    price: 3,
    description: "For large organizations with strict security needs.",
    features: [
      "Everything in Pro",
      "Custom scan configurations",
      "Dedicated account manager",
      "On-premise deployment options",
    ],
  },
];

export default function PricingPage() {
  const router = useRouter();
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);

  const handleSubscribe = async (planName: string) => {
    setLoadingPlan(planName);
    try {
      // 1. Create order
      const res = await fetch("/api/razorpay/create-order", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: planName }),
      });
      
      const order = await res.json();
      if (!res.ok) {
        if (res.status === 401) {
          router.push("/login"); // Redirect if not logged in
        } else {
          alert("Error creating order: " + (order.error || "Unknown"));
        }
        setLoadingPlan(null);
        return;
      }

      // 2. Initialize Razorpay Checkout
      const options = {
        key: process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID, 
        amount: order.amount,
        currency: order.currency,
        name: "SecuriScan",
        description: `Subscription for ${planName} Plan`,
        order_id: order.id,
        handler: async function (response: any) {
          // 3. Verify Payment
          const verifyRes = await fetch("/api/razorpay/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature,
              plan: planName,
            }),
          });
          const verifyData = await verifyRes.json();
          if (verifyRes.ok) {
            alert(`Payment successful! You are now on the ${verifyData.plan} plan.`);
            router.push("/dashboard");
          } else {
            console.error("Verification failed data:", verifyData);
            alert(`Payment verification failed: ${verifyData.error || 'Please contact support.'} ${verifyData.details ? JSON.stringify(verifyData.details) : ''}`);
          }
        },
        prefill: {
          name: "John Doe",
          email: "john@example.com",
          contact: "9999999999",
        },
        theme: {
          color: "#6366f1",
        },
      };

      const rzp = new (window as any).Razorpay(options);
      rzp.on("payment.failed", function (response: any) {
        alert("Payment failed: " + response.error.description);
      });
      rzp.open();
    } catch (error) {
      console.error(error);
      alert("Something went wrong");
    } finally {
      setLoadingPlan(null);
    }
  };

  return (
    <div className="min-h-screen bg-[#0F0F0F] flex flex-col font-sans">
      <Script src="https://checkout.razorpay.com/v1/checkout.js" />
      
      {/* Fixed Navbar */}
      <div className="fixed top-0 left-0 right-0 z-50 border-b border-dashed border-[#52514e] bg-[#0F0F0F]">
        <div className="w-full max-w-7xl mx-auto border-x border-dashed border-[#52514e]">
          <Navbar />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col items-center pt-32 pb-20 px-4 sm:px-6">
        <div className="text-center w-full max-w-3xl mb-16">
          <motion.h1 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-4xl md:text-5xl font-bold text-[#E6ECEC] mb-6 tracking-tight"
          >
            Simple, Transparent Pricing
          </motion.h1>
          <motion.p 
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-lg text-[#E6ECEC]/70"
          >
            Whether you&apos;re an independent developer or a large enterprise, we have a plan that fits your security needs perfectly.
          </motion.p>
        </div>

        <div className="flex flex-wrap justify-center gap-8 w-full max-w-6xl">
          {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index + 0.2 }}
              className={`relative flex flex-col w-full md:w-[350px] p-8 rounded-2xl border ${plan.popular ? 'border-amber-400/50 bg-[#161616]' : 'border-[#38352e] bg-[#111111]'} transition-all hover:scale-[1.02]`}
            >
              {plan.popular && (
                <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-amber-400 text-black text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wider">
                  Most Popular
                </div>
              )}
              
              <h3 className="text-xl font-bold text-[#E6ECEC] mb-2">{plan.name}</h3>
              <div className="my-4">
                <span className="text-4xl font-extrabold text-[#E6ECEC]">₹{plan.price}</span>
                <span className="text-[#E6ECEC]/50 ml-2">/ month</span>
              </div>
              <p className="text-sm text-[#E6ECEC]/60 min-h-[40px] mb-6">{plan.description}</p>
              
              <ul className="flex-1 space-y-4 mb-8">
                {plan.features.map((feature, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm text-[#E6ECEC]/80">
                    <FiCheckCircle className="text-amber-400 shrink-0 mt-0.5" size={16} />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>
              
              <button
                onClick={() => handleSubscribe(plan.name)}
                disabled={loadingPlan === plan.name}
                className={`w-full py-3 px-4 rounded-lg font-medium transition-all ${
                  plan.popular 
                    ? 'bg-amber-400 text-black hover:bg-amber-500' 
                    : 'bg-[#2A2A2A] text-white hover:bg-[#333333]'
                } ${loadingPlan === plan.name ? 'opacity-70 cursor-not-allowed' : ''}`}
              >
                {loadingPlan === plan.name ? 'Processing...' : 'Subscribe Now'}
              </button>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
