const canvas = document.createElement('canvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
canvas.style.position = 'fixed';
canvas.style.top = '0';
canvas.style.left = '0';
canvas.style.opacity = '0.05'; // Very subtle
canvas.style.zIndex = '-1';
canvas.style.pointerEvents = 'none';

document.body.appendChild(canvas);

const letters = Array(256).join(1).split('');

const draw = () => {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#0F0';
    letters.map((y_pos, index) => {
        const text = String.fromCharCode(3e4 + Math.random() * 33);
        const x_pos = index * 10;
        ctx.fillText(text, x_pos, y_pos);
        letters[index] = (y_pos > 758 + Math.random() * 1e4) ? 0 : y_pos + 10;
    });
};

setInterval(draw, 33);

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});
