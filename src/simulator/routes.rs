use rand::Rng;

#[derive(Clone)]
pub struct Route {
    pub path: &'static str,
    pub method: &'static str,
    pub controller: &'static str,
    pub action: &'static str,
    pub weight: u32,
    pub base_ms: f64,
    pub db_queries: i32,
}

pub const ROUTES: &[Route] = &[
    // High traffic, fast
    Route { path: "/", method: "GET", controller: "HomeController", action: "index", weight: 20, base_ms: 50.0, db_queries: 3 },
    Route { path: "/products", method: "GET", controller: "ProductsController", action: "index", weight: 15, base_ms: 80.0, db_queries: 5 },
    Route { path: "/products/:id", method: "GET", controller: "ProductsController", action: "show", weight: 25, base_ms: 60.0, db_queries: 4 },

    // Medium traffic
    Route { path: "/cart", method: "GET", controller: "CartController", action: "show", weight: 10, base_ms: 70.0, db_queries: 6 },
    Route { path: "/cart/items", method: "POST", controller: "CartItemsController", action: "create", weight: 8, base_ms: 100.0, db_queries: 8 },
    Route { path: "/search", method: "GET", controller: "SearchController", action: "index", weight: 10, base_ms: 150.0, db_queries: 12 },

    // Low traffic, slower
    Route { path: "/checkout", method: "GET", controller: "CheckoutController", action: "show", weight: 5, base_ms: 120.0, db_queries: 10 },
    Route { path: "/checkout", method: "POST", controller: "CheckoutController", action: "create", weight: 3, base_ms: 300.0, db_queries: 15 },
    Route { path: "/orders/:id", method: "GET", controller: "OrdersController", action: "show", weight: 4, base_ms: 90.0, db_queries: 7 },

    // Admin (slow, N+1 prone)
    Route { path: "/admin/dashboard", method: "GET", controller: "Admin::DashboardController", action: "index", weight: 2, base_ms: 400.0, db_queries: 50 },
    Route { path: "/admin/users", method: "GET", controller: "Admin::UsersController", action: "index", weight: 1, base_ms: 350.0, db_queries: 40 },
    Route { path: "/admin/orders", method: "GET", controller: "Admin::OrdersController", action: "index", weight: 1, base_ms: 500.0, db_queries: 80 },

    // API endpoints
    Route { path: "/api/v1/products", method: "GET", controller: "Api::V1::ProductsController", action: "index", weight: 8, base_ms: 40.0, db_queries: 2 },
    Route { path: "/api/v1/products/:id", method: "GET", controller: "Api::V1::ProductsController", action: "show", weight: 6, base_ms: 30.0, db_queries: 1 },
];

pub fn pick_random() -> &'static Route {
    let mut rng = rand::thread_rng();
    let total_weight: u32 = ROUTES.iter().map(|r| r.weight).sum();
    let mut pick = rng.gen_range(0..total_weight);

    for route in ROUTES {
        if pick < route.weight {
            return route;
        }
        pick -= route.weight;
    }

    &ROUTES[0]
}

#[derive(Clone)]
pub struct SimulatedError {
    pub class: &'static str,
    pub message: &'static str,
    pub weight: u32,
}

pub const ERRORS: &[SimulatedError] = &[
    SimulatedError {
        class: "ActiveRecord::RecordNotFound",
        message: "Couldn't find Product with 'id'={}",
        weight: 40,
    },
    SimulatedError {
        class: "ActionController::ParameterMissing",
        message: "param is missing or the value is empty: {}",
        weight: 20,
    },
    SimulatedError {
        class: "ActiveRecord::RecordInvalid",
        message: "Validation failed: {} can't be blank",
        weight: 15,
    },
    SimulatedError {
        class: "Redis::ConnectionError",
        message: "Connection refused - connect(2) for 127.0.0.1:6379",
        weight: 5,
    },
    SimulatedError {
        class: "Net::ReadTimeout",
        message: "Net::ReadTimeout with #<TCPSocket:(closed)>",
        weight: 5,
    },
];

pub fn pick_random_error() -> &'static SimulatedError {
    let mut rng = rand::thread_rng();
    let total_weight: u32 = ERRORS.iter().map(|e| e.weight).sum();
    let mut pick = rng.gen_range(0..total_weight);

    for error in ERRORS {
        if pick < error.weight {
            return error;
        }
        pick -= error.weight;
    }

    &ERRORS[0]
}
