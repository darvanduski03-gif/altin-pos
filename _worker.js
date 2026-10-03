export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      // 1. Fetch All Data (GET)
      if (path === "/api/all" && request.method === "GET") {
        const products = await env.DB.prepare("SELECT * FROM products").all();
        const sales = await env.DB.prepare("SELECT * FROM sales").all();
        const purchases = await env.DB.prepare("SELECT * FROM purchases").all();
        const expenses = await env.DB.prepare("SELECT * FROM expenses").all();
        const debts = await env.DB.prepare("SELECT * FROM debts").all();
        const returns = await env.DB.prepare("SELECT * FROM returns").all();

        const parseJSON = (arr) => arr.results.map(item => {
          if (item.items) item.items = JSON.parse(item.items);
          return item;
        });

        return Response.json({
          products: products.results, sales: parseJSON(sales),
          purchases: purchases.results, expenses: expenses.results,
          debts: debts.results, returns: parseJSON(returns)
        }, { headers: corsHeaders });
      }

      // 2. Add New Data (POST)
      if (path.startsWith("/api/") && request.method === "POST") {
        const parts = path.split("/");
        const table = parts[2]; // e.g., "products", "sales", "purchases", "expenses", "debts", "returns"
        const data = await request.json();

        if (table === "products") {
          await env.DB.prepare(`INSERT INTO products (id, name, code, buy, sell, qty, min) VALUES (?, ?, ?, ?, ?, ?, ?)`)
            .bind(data.id, data.name, data.code, data.buy, data.sell, data.qty, data.min).run();
        } 
        else if (table === "sales" || table === "returns") {
          const itemsStr = JSON.stringify(data.items);
          await env.DB.prepare(`INSERT INTO ${table} (id, date, items, total, customer, customerPhone, paymentType, previousDebt, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
            .bind(data.id, data.date, itemsStr, data.total, data.customer, data.customerPhone || null, data.paymentType || null, data.previousDebt || null, data.reason || null).run();
        }
        else if (table === "purchases") {
          await env.DB.prepare(`INSERT INTO purchases (id, product, qty, price, supplier, date) VALUES (?, ?, ?, ?, ?, ?)`)
            .bind(data.id, data.product, data.qty, data.price, data.supplier, data.date).run();
        }
        else if (table === "expenses") {
          await env.DB.prepare(`INSERT INTO expenses (id, name, amount, date) VALUES (?, ?, ?, ?)`)
            .bind(data.id, data.name, data.amount, data.date).run();
        }
        else if (table === "debts") {
          await env.DB.prepare(`INSERT INTO debts (id, name, amount, note, date) VALUES (?, ?, ?, ?, ?)`)
            .bind(data.id, data.name, data.amount, data.note, data.date).run();
        }

        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // 3. Update Existing Data (PUT)
      if (path.startsWith("/api/") && request.method === "PUT") {
        const parts = path.split("/");
        const table = parts[2];
        const id = parts[3];
        const data = await request.json();

        if (table === "products") {
          await env.DB.prepare(`UPDATE products SET name = ?, code = ?, buy = ?, sell = ?, qty = ?, min = ? WHERE id = ?`)
            .bind(data.name, data.code, data.buy, data.sell, data.qty, data.min, id).run();
        }
        else if (table === "debts") {
          await env.DB.prepare(`UPDATE debts SET amount = ? WHERE id = ?`)
            .bind(data.amount, id).run();
        }

        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // 4. Delete Data (DELETE)
      if (path.startsWith("/api/") && request.method === "DELETE") {
        const parts = path.split("/");
        await env.DB.prepare(`DELETE FROM ${parts[2]} WHERE id = ?`).bind(parts[3]).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

    } catch (err) {
      return new Response(err.message, { status: 500, headers: corsHeaders });
    }

    // Serve Static Assets (index.html, etc.)
    return env.ASSETS.fetch(request);
  }
};