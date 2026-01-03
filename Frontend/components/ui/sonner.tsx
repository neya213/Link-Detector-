"use client"

import { Toaster as Sonner, type ToasterProps } from "sonner"

const Toaster = ({ ...props }: ToasterProps) => {
  return (
    <Sonner
      theme="dark"
      className="toaster group"
      toastOptions={{
        classNames: {
          toast: "group toast",
          title: "text-sm font-semibold",
          description: "text-sm opacity-90",
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
