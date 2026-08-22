/**
 * Bootstrap. The chrome (top bar, hero, footer) is in index.html so it renders
 * with JavaScript disabled; everything below the hero is built here.
 */
import './style.css';
import { App } from './ui/app';

const root = document.getElementById('exhibits');

if (root instanceof HTMLElement) {
  const app = new App(root);
  void app.mount().then(() => {
    document.documentElement.setAttribute('data-app-ready', 'true');
  });
}
