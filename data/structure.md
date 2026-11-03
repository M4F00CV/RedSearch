## **name: code-documentation description: Document and validate code clearly, concisely, and professionally for Python, C#, Vue 3, and Docker. Integrates PEP 8 guidelines, official .NET conventions, clean code principles, SOLID, and modularization. license: MIT**

# **Code Documentation and Quality Rules**

All documentation generated and code analysis performed by GitHub Copilot for this project must be clear, useful, professional, and written under the following design, style, and technology standards.

## **GOLDEN RULES FOR DOCUMENTATION**

* **LANGUAGE**: All generated documentation and comments MUST be written **exclusively in ENGLISH**.  
* **CLARITY OVER QUANTITY**: A concise comment explaining the "what" and "why" is better than redundant paragraphs explaining the obvious.  
* **INTENT, NOT IMPLEMENTATION**: Document the logical intent of the code, not how it is syntactically written.  
* **SELF-EXPLANATORY CODE**: If a variable, function, or method is fully self-explanatory by its naming, **DO NOT add comments**.  
* Always document **edge cases, critical assumptions, and side effects**.

## **DESIGN AND CODE QUALITY REVIEW (SOLID, CLEAN CODE, OOP)**

Before generating documentation for any code snippet, Copilot must evaluate whether the design complies with architectural best practices. If severe violations are detected, politely suggest a code refactoring alongside the documentation proposal:

### **1. SOLID Principles**

* **S (Single Responsibility)**: Does the class, function, or component do only one thing? If it has more than one reason to change, suggest splitting it.  
* **O (Open/Closed)**: Is the code structured so that its behavior can be extended without modifying its source code? (e.g., using polymorphism or abstractions).  
* **L (Liskov Substitution)**: Subclasses or derived components must be usable in place of their base classes without breaking program behavior.  
* **I (Interface Segregation)**: Do not force components, services, or classes to depend on interfaces or methods they do not use.  
* **D (Dependency Inversion)**: Depend on abstractions, not on concrete implementations. Encourage the use of dependency injection (DI).

### **2. Clean Code**

* **Reveal Intent**: Variables, methods, and classes must clearly indicate their purpose (avoid confusing abbreviations like temp, data, handler).  
* **Small Functions**: Functions and methods should be as small as possible (ideally under 20 lines) and perform a single logical operation.  
* **Side Effects**: Warn and document if a function modifies global states or external variables in a non-obvious way.

## **WHERE DOCUMENTATION GOES: DECLARATION VS. BODY**

* **Declaration (When creating classes, interfaces, methods, functions, or components)**: Use full formal documentation blocks (""" ... """, /// ..., / ... */) according to the standard of the chosen technology. It must include description, parameters, types, returns, and exceptions.  
* **Body (Inside functions or methods)**: Use **single-line comments only** (#, //), clear and concise. Only where they add real value (such as a complex step or a technical decision of why it was done that way). Avoid large blocks of commented-out text.

## **STANDARDS BY LANGUAGE AND TECHNOLOGY**

### **1. Python (PEP 8 & PEP 257 - Google Style)**

Always follow the **PEP 8** style guide (naming in snake_case, variables in lowercase, classes in PascalCase, two spaces before inline comments).

For docstrings, follow **PEP 257** conventions using the Google style format with strict typing (Type Hints).

from typing import Dict, List

class OrderProcessor:  
    """Manages order processing and dispatching within the system.

    Attributes:  
        inventory_client: Database client connection for stock management.  
    """

    def __init__(self, inventory_client) -> None:  
        self.inventory_client = inventory_client

    def process_order(self, order_id: int, items: List[Dict], coupon: str = None) -> bool:  
        """Processes an order and updates the available stock.

        Args:  
            order_id: Unique identifier for the order.  
            items: A list of dictionaries containing product ID and quantity.  
            coupon: Optional discount code to apply.

        Returns:  
            True if the order was processed successfully, False otherwise.

        Raises:  
            ValueError: If the items list is empty.  
            InsufficientStockError: If any product quantity exceeds available physical stock.  
        """  
        if not items:  
            raise ValueError("The items list cannot be empty")  
          
        # Iterate to validate stock before committing the transaction  
        for item in items:  
            if not self.inventory_client.has_stock(item["id"], item["quantity"]):  
                raise InsufficientStockError(f"Out of stock for product {item['id']}")

        return self.inventory_client.deduct_items(items)

### **2. C# (.NET Coding Conventions & XML Docs)**

Follow official Microsoft .NET coding standards:

* PascalCase for class names, methods, properties, and namespaces.  
* camelCase for local variables and method parameters.  
* Use the var keyword when the data type is obvious from the right side of the assignment.  
* Use XML documentation comments (///) for all public types and members.

using System;  
using System.Collections.Generic;

namespace MyProject.Services  
{  
    /// <summary>  
    /// Provides services for calculating and processing employee payrolls.  
    /// </summary>  
    public class PayrollCalculator  
    {  
        private readonly double _baseTaxRate = 0.16;

        /// <summary>  
        /// Calculates the final net salary applying deductions and taxes.  
        /// </summary>  
        /// <param name="hoursWorked">Total amount of hours worked in the month.</param>  
        /// <param name="hourlyRate">Hourly payment rate established in USD.</param>  
        /// <returns>The calculated net salary after taxes.</returns>  
        /// <exception cref="ArgumentException">Thrown if hours or rate are negative.</exception>  
        public double CalculateNetSalary(double hoursWorked, double hourlyRate)  
        {  
            if (hoursWorked < 0 || hourlyRate < 0)  
            {  
                throw new ArgumentException("Hours worked and hourly rate must be greater than or equal to zero.");  
            }

            var grossSalary = hoursWorked * hourlyRate;

            // Apply a base 16% tax deduction on gross salary  
            var taxDeduction = grossSalary * _baseTaxRate;

            return grossSalary - taxDeduction;  
        }  
    }  
}

### **3. Vue 3 (Composition API, SFC & JSDoc)**

Write components using Single File Components (.vue) with <script setup> syntax using TypeScript or modern JavaScript.

* Document the interface of Props and Emits.  
* Use camelCase for props and variables, and PascalCase for imported components.  
* Add practical usage examples using @example.

<script setup lang="ts">  
import { computed } from 'vue';

interface AlertMessageProps {  
  /** Alert type that defines the visual layout of the component */  
  type?: 'success' | 'error' | 'warning' | 'info';  
  /** Descriptive title for the alert */  
  title: string;  
  /** Detailed body informational message */  
  message: string;  
}

const props = withDefaults(defineProps<AlertMessageProps>(), {  
  type: 'info'  
});

const emits = defineEmits<{  
  /** Fired when the user clicks the close button */  
  (e: 'close'): void;  
}>();

// Compute Tailwind CSS classes based on selected alert type  
const alertClasses = computed(() => {  
  return {  
    'bg-green-50 text-green-800 border-green-200': props.type === 'success',  
    'bg-red-50 text-red-800 border-red-200': props.type === 'error',  
    'bg-yellow-50 text-yellow-800 border-yellow-200': props.type === 'warning',  
    'bg-blue-50 text-blue-800 border-blue-200': props.type === 'info',  
  };  
});  
</script>

<template>  
  <div class="border p-4 rounded-md flex justify-between" :class="alertClasses">  
    <div>  
      <h3 class="font-bold text-sm">{{ title }}</h3>  
      <p class="text-xs mt-1">{{ message }}</p>  
    </div>  
    <button @click="emits('close')" class="text-sm font-semibold hover:opacity-75">  
      ✕  
    </button>  
  </div>  
</template>

### **4. Docker (Dockerfile & Docker Compose)**

Write robust and optimized configurations for containerized environments:

* Follow Docker best practices (e.g., group commands like RUN apt-get update && apt-get install -y... to reduce layers).  
* Use clear explanatory comments # before key operations (setting environment variables, copying binaries, exposing ports).  
* Document major services, networks, and volumes in docker-compose.yml.

*Example of a documented Dockerfile:*

# --- Build Stage (Multi-stage Build) ---  
FROM node:20-alpine AS build  
WORKDIR /app

# Copy dependency files first to leverage Docker layer caching  
COPY package*.json ./  
RUN npm ci

COPY . .  
RUN npm run build

# --- Production Stage (Optimized Final Container) ---  
FROM nginx:alpine  
WORKDIR /usr/share/nginx/html

# Clean default static assets from nginx  
RUN rm -rf ./*

# Copy build artifacts generated from the previous stage  
COPY --from=build /app/dist .

# Expose port configured according to local server infrastructure  
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

*Example of a documented Docker Compose:*

version: '3.8'

services:  
  # Application Backend Service  
  api:  
    build:  
      context: ./backend  
      dockerfile: Dockerfile  
    ports:  
      - "8000:8000"  
    environment:  
      - DATABASE_URL=postgres://user:pass@db:5432/app_db  
    # Ensure database is ready before initializing the API  
    depends_on:  
      - db  
    networks:  
      - app-network

  # PostgreSQL Database Engine  
  db:  
    image: postgres:15-alpine  
    environment:  
      - POSTGRES_USER=user  
      - POSTGRES_PASSWORD=pass  
      - POSTGRES_DB=app_db  
    volumes:  
      - pg-data:/var/lib/postgresql/data  
    networks:  
      - app-network

volumes:  
  pg-data:  
    driver: local

networks:  
  app-network:  
    driver: bridge

## **README.md GENERATION AND MAINTENANCE**

When requested to create, update, or structure the project's README.md file, Copilot must follow this professional standard structure:

### **1. Standard Document Structure**

Every generated README.md must have the following sections organized hierarchically:

* **Project Title**: A clear name and an attractive one-line description of what the project does.  
* **Badges**: (Optional) Build status, coverage, version, key technologies.  
* **Key Features**: A short bulleted list highlighting key functionalities.  
* **Technologies Used**: Clear icons or mentions of technologies (e.g., Python 3.11, .NET 8, Vue 3, Docker).  
* **Prerequisites**: Minimum required software (e.g., Docker, Node.js, .NET SDK).  
* **Installation and Setup**: Exact numbered steps and clean commands to clone the repository, install dependencies, and run the environment.  
* **Env Variables / Configuration**: A table documenting required .env variables or configurations.  
* **Usage and Examples**: Small code snippets showing how to initialize or spin up the project (e.g., docker compose up -d).  
* **Running Tests**: Commands needed to run the suite of unit or integration tests.  
* **License**: Project license type (e.g., MIT, Apache 2.0).

### **2. README Style Rules**

* **Tone**: Technical, professional, and welcoming to other developers.  
* **Syntax Highlighting**: Always specify the language in code blocks (e.g., ```bash, ```dockerfile, ```csharp).  
* **Emoji Usage**: Use emojis soberly as visual guides (e.g., 🚀 for quick start, 🛠️ for setup, 📦 for dependencies, 🧪 for tests).

## **USEFUL INLINE COMMENTS (INSIDE THE BODY)**

Use standardized prefixes for important development notes using your language's single-line comment syntax (# or //):

// HACK: API returns timestamps in PST, but technical specification requires UTC  
const dateTime = convertToUTC(response.timestamp, 'America/Los_Angeles');

// FIXME: This regular expression fails if there are special Unicode characters in the name  
if (!/^[a-zA-Z\s]+$/.test(name)) { ... }

// TODO: Implement rate limiting once Redis is set up  
await makeRequest(url);

// Edge case: avoid division by zero if the array is empty  
const average = values.length > 0 ? sum(values) / values.length : 0;

## **CHECKLIST BEFORE DELIVERING RESPONSES**

When generating documentation for Python, C#, Vue 3, or Docker, or when generating a README, validate:

1. **Language**: Is all documentation, the README, and comments written in ENGLISH?  
2. **Architecture and Quality**: Does the code comply with SOLID, OOP, modularization, and clean code principles? (If not, suggest refactoring to the user).  
3. **README Structure**: If it is a README file, does it have installation, environment variable configuration in a table, technologies, and license?  
4. **Correct Documentation Styles**:  
   * **Python**: Google Docstring style + PEP 8.  
   * **C#**: XML comments (///) + .NET Conventions.  
   * **Vue 3**: Composition API (<script setup>) + JSDoc/TSDoc for Prop interfaces.  
   * **Docker**: Clear direct comments for layers and dependencies.  
5. **Inline Comments**: Do comments inside the body use only # or // and explain "why" instead of repeating the code?