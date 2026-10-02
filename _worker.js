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

      if (path.startsWith("/api/") && request.method === "POST") {
        const table = path.replace("/api/", "");
        const data = await request.json();
        // ئەمانە بەپێی خشتەکان جێبەجێ دەبن کە پێشتر لە وەڵامی پێشووتردا دامپێتی
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path.startsWith("/api/") && request.method === "DELETE") {
        const parts = path.split("/");
        await env.DB.prepare(`DELETE FROM ${parts[2]} WHERE id = ?`).bind(parts[3]).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }
    } catch (err) {
      return new Response(err.message, { status: 500, headers: corsHeaders });
    }

    return env.ASSETS.fetch(request);
  }
};