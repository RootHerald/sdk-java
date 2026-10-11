package io.rootherald;

/**
 * The budget a 429 {@code budget_exhausted} names, as the server sends it.
 *
 * @param id   the budget's id
 * @param name the budget's name, as shown in the dashboard
 */
public record RefusingBudget(String id, String name) {
}
