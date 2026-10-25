import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from hotturkey.engine import Engine, password_hash, password_ok
from hotturkey.model import matches, validate_block, spans, PolicyError
from hotturkey.store import Store

class Clock:
    def __init__(self):self.value=dt.datetime(2026,10,19,9,0).timestamp();self.mono=1000
    def wall(self):return self.value
    def monotonic(self):return self.mono
    def advance(self,seconds):self.value+=seconds;self.mono+=seconds

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock();self.engine=Engine(self.store,self.clock.wall,self.clock.monotonic,"boot-1","alice")
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def make(self,**kw):
        if kw.get('device','none')!='none' and not self.store.state['settings']['device_recovery_hash']:self.engine.configure_device_recovery('fixture-escape')
        value={"name":"Work","enabled":True,"websites":["example.com"],**kw}
        return self.engine.find(self.engine.save_block(value)["id"])
    def check(self,url="https://example.com",**kw):return self.engine.evaluate(url,**kw)["blocked"]
    def raises(self,fn,*args,**kw):self.assertRaises(PolicyError,fn,*args,**kw)

    def test_domain_boundary_and_subdomains(self):
        self.assertTrue(matches("example.com","https://sub.example.com/a"));self.assertFalse(matches("example.com","https://evil-example.com"));self.assertFalse(matches("example.com","https://example.com.evil.org"))
    def test_browser_page_specification_cases(self):
        for pattern,url,expected in json.loads((Path(__file__).parent/'browser_page_cases.json').read_text()):
            with self.subTest(pattern=pattern,url=url):self.assertEqual(matches(pattern,url),expected)
    def test_browser_page_exceptions_and_independent_rules(self):
        self.make(websites=['edge://settings'],exceptions=['edge://settings/downloads'])
        self.assertTrue(self.check('edge://settings/privacy'))
        self.assertFalse(self.check('edge://settings/downloads'))
        self.make(name='Second',websites=['edge://settings/downloads'])
        self.assertTrue(self.check('edge://settings/downloads'))
    def test_browser_pages_honor_breaks_enabled_and_background_settings(self):
        b=self.make(websites=['edge://settings'],**{'break':{'type':'allowance','allowance_minutes':1}})
        self.assertFalse(self.check('edge://settings/'))
        self.store.charge(self.clock.value,b['id'],60)
        self.assertTrue(self.check('edge://settings/'))
        self.assertFalse(self.check('edge://settings/',active=False))
        self.store.state['settings']['block_inactive']=True
        self.assertTrue(self.check('edge://settings/',active=False))
        self.engine.toggle(b['id'],False)
        self.assertFalse(self.check('edge://settings/'))
    def test_path_prefix(self):
        self.assertTrue(matches("reddit.com/r/work","https://www.reddit.com/r/work/top"));self.assertFalse(matches("reddit.com/r/work","https://reddit.com/r/funny"))
    def test_glob_search_decodes_keywords(self):
        self.assertTrue(matches("google.com/*q=*hello world*","https://google.com/search?q=hello%20world"))
    def test_internet_excludes_file(self):
        self.assertTrue(matches("*.*","https://example.com"));self.assertFalse(matches("*.*","file:///tmp/a.pdf"))
    def test_explicit_scheme(self):
        self.assertTrue(matches("http://example.com","http://example.com/a"));self.assertFalse(matches("http://example.com","https://example.com/a"))
    def test_idn(self):self.assertTrue(matches("例子.中国","https://xn--fsqu00a.xn--fiqs8s/a"))
    def test_glob_keywords(self):self.assertTrue(matches("*unicorn*","https://google.com/search?q=unicorn"))
    def test_adult_tld(self):self.assertTrue(matches("*.xxx","https://a.xxx/a"));self.assertFalse(matches("*.xxx","https://a.xxx.evil.com"))
    def test_domain_wildcard_does_not_match_path(self):self.assertFalse(matches("*.xxx","https://example.com/file.xxx"))
    def test_query_delimiter_is_literal(self):
        self.assertTrue(matches("example.com/*?q=*","https://example.com/search?q=x"))
        self.assertFalse(matches("example.com/*?q=*","https://example.com/searchaq=x"))
    def test_independent_exceptions(self):
        self.make(exceptions=["example.com/learn"]);self.assertFalse(self.check("https://example.com/learn"));self.make(name="Strict");self.assertTrue(self.check("https://example.com/learn"))
    def test_channel_block(self):self.make(websites=["youtube.com/@gaming"]);self.assertTrue(self.check("https://youtube.com/watch?v=x",channels=["https://youtube.com/@gaming"]))
    def test_channel_exception(self):self.make(websites=["youtube.com"],exceptions=["youtube.com/@learn"]);self.assertFalse(self.check("https://youtube.com/watch?v=x",channels=["https://youtube.com/@learn"]))
    def test_channel_metadata_pending(self):
        self.make(websites=["youtube.com"],exceptions=["youtube.com/@learn"])
        self.assertTrue(self.engine.evaluate("https://youtube.com/watch?v=x")["pending_channel"])
        self.assertFalse(self.engine.evaluate("https://youtube.com/watch?v=x",channels=["https://youtube.com/@learn"])["pending_channel"])
    def test_disabled(self):self.make(enabled=False);self.assertFalse(self.check())
    def test_user_selection(self):self.make(users=["bob"]);self.assertFalse(self.check())
    def test_background_and_embeds(self):
        self.make();self.assertFalse(self.check(active=False));self.assertTrue(self.check(embedded=True));self.store.state["settings"]["block_embeds"]=False;self.assertFalse(self.check(embedded=True))
    def test_files(self):
        self.make(websites=["file://*"]);self.assertFalse(self.check("file:///tmp/a"));self.store.state["settings"]["allow_files"]=False;self.assertTrue(self.check("file:///tmp/a"))
    def test_schedule_boundary(self):
        self.make(mode="scheduled",schedule=[{"days":[0],"start":540,"end":600}]);self.assertTrue(self.check());self.clock.advance(3600);self.assertFalse(self.check())
    def test_overnight(self):
        self.make(mode="scheduled",schedule=[{"days":[6],"start":1380,"end":600}]);self.assertTrue(self.check());self.clock.advance(3600);self.assertFalse(self.check())
    def test_overlap_rejected_including_wrap(self):self.raises(spans,[{"days":[6],"start":1380,"end":600},{"days":[0],"start":540,"end":660}])
    def test_adjacent_spans_allowed(self):self.assertEqual(len(spans([{"days":[0],"start":540,"end":600},{"days":[0],"start":600,"end":660}])),2)
    def test_empty_schedule_rejected(self):self.raises(self.make,mode="scheduled")
    def test_schedule_break_override(self):
        self.make(mode="scheduled",schedule=[{"days":[0],"start":540,"end":600,"break":{"type":"allowance","allowance_minutes":1}}]);self.assertFalse(self.check())
    def test_timer_protects_replacement_and_removal(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+60});self.raises(self.engine.toggle,b["id"]);self.raises(self.engine.delete,b["id"]);self.raises(self.engine.save_block,b,b["id"]);self.raises(self.engine.unlock,b["id"],{})
    def test_all_locks_allow_additions_and_preserve_other_policy(self):
        locks=[{'type':'timer','until':self.clock.value+60},
               {'type':'range','schedule':[{'days':[0],'start':540,'end':600}]},
               {'type':'text','length':10},{'type':'password','password':'secret'},
               {'type':'delay','minutes':1},{'type':'schedule'},{'type':'restart'}]
        for lock in locks:
            with self.subTest(lock=lock['type']):
                b=self.make(name=lock['type'],mode='scheduled',schedule=[{'days':[0],'start':540,'end':600}],applications=['bundle:existing.app'])
                self.engine.set_lock(b['id'],lock)
                self.engine.status(b)
                before=copy.deepcopy(b);runtime=copy.deepcopy(self.store.state['runtime'])
                result=self.engine.add_targets(b['id'],[' example.com ','new.example','new.example'],['bundle:new.app'])
                self.assertTrue(result['locked'])
                self.assertTrue(self.check('https://new.example'))
                self.assertTrue(self.engine.app_matches(b,{'bundle':'new.app'}))
                expected={**before,'websites':['example.com','new.example'],'applications':['bundle:existing.app','bundle:new.app']}
                self.assertEqual(b,expected)
                self.assertEqual(self.store.state['runtime'],runtime)
                # Replacement, exceptions and enablement still cannot be changed via save.
                self.raises(self.engine.save_block,{**b,'websites':['new.example'],'exceptions':['*.*'],'enabled':False},b['id'])
                self.assertEqual(b,expected)
    def test_additions_merge_with_latest_targets_and_survive_reload(self):
        b=self.make();self.engine.set_lock(b['id'],{'type':'password','password':'secret'})
        self.engine.add_targets(b['id'],['first.example'])
        self.engine.add_targets(b['id'],['second.example'],['bundle:second.app'])
        self.engine.add_targets(b['id'],['first.example'])
        other=Store(self.temp.name)
        try:
            saved=Engine(other,self.clock.wall,self.clock.monotonic,'boot-1','alice').find(b['id'])
            self.assertEqual(saved['websites'],['example.com','first.example','second.example'])
            self.assertEqual(saved['applications'],['bundle:second.app'])
            self.assertTrue(password_ok('secret',saved['lock']['hash']))
        finally:other.db.close()
    def test_invalid_additions_are_atomic_including_combined_limit(self):
        b=self.make();before=copy.deepcopy(b)
        for websites,applications in [(['new.example'],[123]),({'bad':'type'},[]),(['bad\x00host'],[]),(['x'*2049],[])]:
            self.raises(self.engine.add_targets,b['id'],websites,applications)
            self.assertEqual(b,before)
        b['applications']=['bundle:app'+str(i) for i in range(10000)]
        self.raises(self.engine.add_targets,b['id'],['new.example'],['bundle:overflow'])
        self.assertEqual(b['websites'],['example.com'])
        self.assertEqual(len(b['applications']),10000)
    def test_additions_preserve_break_usage_and_pending_challenges(self):
        for typ in ['allowance','sessions','reward','text','delay','pomodoro']:
            with self.subTest(type=typ):
                b=self.make(name=typ,**{'break':{'type':typ,'custom_text':'focus'}})
                self.engine.set_lock(b['id'],{'type':'timer','until':self.clock.value+3600})
                if typ in {'text','delay'}:self.engine.request_break(b['id'],{})
                self.engine.status(b)
                self.engine.runtime(b).update(reward_credit=17,sessions_used=2,focus_seconds=13)
                self.store.charge(self.clock.value,b['id'],23)
                before=copy.deepcopy(self.engine.runtime(b))
                self.engine.add_targets(b['id'],['new.example'])
                self.assertEqual(self.engine.runtime(b),before)
                self.assertEqual(self.store.used(b['id'],0),23)
    def test_additions_preserve_device_deadline_and_disabled_rule(self):
        b=self.make(device='lock',device_minutes=5,confirm_device=True)
        before=copy.deepcopy(b['lock']);runtime=copy.deepcopy(self.engine.runtime(b))
        self.engine.add_targets(b['id'],['new.example'])
        self.assertEqual(b['lock'],before);self.assertEqual(self.engine.runtime(b),runtime)
        other=self.make(name='Paused',enabled=False)
        self.engine.set_lock(other['id'],{'type':'restart'})
        result=self.engine.add_targets(other['id'],['paused.example'])
        self.assertFalse(result['enabled']);self.assertFalse(result['active']);self.assertTrue(result['locked'])
    def test_timer_expires(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+60});self.clock.advance(60);self.assertFalse(self.engine.locked(b));self.engine.toggle(b["id"],False);self.assertFalse(self.check())
    def test_timer_only_extends(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+60});self.raises(self.engine.set_lock,b["id"],{"type":"timer","until":self.clock.value+30});self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+120});self.clock.advance(90);self.assertTrue(self.engine.locked(b))
    def test_password_lock(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"password","password":"abc"});self.assertNotIn("hash",self.engine.status(b)["lock"]);self.raises(self.engine.unlock,b["id"],{"answer":"wrong"});self.clock.advance(3);self.engine.unlock(b["id"],{"answer":"abc"});self.assertFalse(self.engine.locked(b))
    def test_text_lock(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"text","length":100});text=b["lock"]["text"];self.assertEqual(len(text),100);self.raises(self.engine.unlock,b["id"],{"answer":text[:-1]});self.engine.unlock(b["id"],{"answer":text});self.assertFalse(self.engine.locked(b))
    def test_word_lock(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"text","length":150,"text_mode":"words"});self.assertIn(" ",b["lock"]["text"]);self.assertEqual(len(b["lock"]["text"]),150)
    def test_text_lock_extension_only_appends_and_preserves_policy_runtime(self):
        b=self.make();self.engine.set_lock(b['id'],{'type':'text','length':20})
        text=b['lock']['text'];before=copy.deepcopy(b);runtime=copy.deepcopy(self.engine.runtime(b))
        result=self.engine.set_lock(b['id'],{'type':'text','length':50,'custom_text':'replacement','text_mode':'words'})
        self.assertTrue(result['locked']);self.assertEqual(len(b['lock']['text']),50);self.assertTrue(b['lock']['text'].startswith(text))
        expected=copy.deepcopy(before);expected['lock']['text']=b['lock']['text']
        self.assertEqual(b,expected);self.assertEqual(self.engine.runtime(b),runtime)
        self.raises(self.engine.unlock,b['id'],{'answer':text})
        self.engine.unlock(b['id'],{'answer':b['lock']['text']});self.assertFalse(self.engine.locked(b))
    def test_text_lock_extension_invalid_lengths_are_atomic(self):
        b=self.make();self.engine.set_lock(b['id'],{'type':'text','length':20});before=copy.deepcopy(b)
        for length in [0,19,20,5001,True,21.5,'50',None]:
            self.raises(self.engine.set_lock,b['id'],{'type':'text','length':length})
            self.assertEqual(b,before)
        self.raises(self.engine.set_lock,b['id'],{'type':'password','password':'replacement'})
        self.assertEqual(b,before)
    def test_word_custom_and_legacy_text_extensions_persist(self):
        for name,options in [('words',{'length':20,'text_mode':'words'}),('custom',{'custom_text':'专注🔥\n继续'}),('legacy',{'length':20})]:
            with self.subTest(kind=name):
                b=self.make(name=name);self.engine.set_lock(b['id'],{'type':'text',**options})
                if name=='legacy':b['lock'].pop('text_mode')
                text=b['lock']['text']
                self.engine.set_lock(b['id'],{'type':'text','length':len(text)+1})
                self.assertEqual(len(b['lock']['text']),len(text)+1);self.assertTrue(b['lock']['text'].startswith(text))
                self.engine.set_lock(b['id'],{'type':'text','length':5000})
                self.assertEqual(len(b['lock']['text']),5000);self.assertTrue(b['lock']['text'].startswith(text))
                other=Store(self.temp.name)
                try:self.assertEqual(other.state['blocks'][-1]['lock'],b['lock'])
                finally:other.db.close()
    def test_delay_lock_survives_restart(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"delay","minutes":1});self.assertIn("ready_at",self.engine.unlock(b["id"],{}));self.engine=Engine(self.store,self.clock.wall,self.clock.monotonic,"boot-1","alice");self.clock.advance(59);self.raises(self.engine.unlock,b["id"],{});self.clock.advance(1);self.engine.unlock(b["id"],{})
    def test_restart_lock_actual_boot_only(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"restart"});self.assertTrue(self.engine.locked(b));self.engine=Engine(self.store,self.clock.wall,self.clock.monotonic,"boot-2","alice");self.assertFalse(self.engine.locked(b))
    def test_range_lock(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"range","schedule":[{"days":[0],"start":540,"end":600}]});self.assertTrue(self.engine.locked(b));self.clock.advance(3600);self.assertFalse(self.engine.locked(b))
    def test_inverse_range_lock(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"range","schedule":[{"days":[0],"start":540,"end":600}],"allow_inside":True});self.assertFalse(self.engine.locked(b));self.clock.advance(3600);self.assertTrue(self.engine.locked(b))
    def test_schedule_lock_advance(self):
        b=self.make(mode="scheduled",schedule=[{"days":[0],"start":600,"end":660}]);self.engine.set_lock(b["id"],{"type":"schedule","before_minutes":30});self.assertFalse(self.engine.locked(b));self.clock.advance(1800);self.assertTrue(self.engine.locked(b))
    def test_clock_rollback(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+60});self.clock.value-=86400;self.clock.mono+=60;self.assertFalse(self.engine.locked(b))
    def test_lock_injection_ignored(self):
        b=self.make(lock={"type":"password","hash":"injected"});self.assertEqual(b["lock"],{"type":"none"})
    def test_pomodoro(self):
        self.make(**{"break":{"type":"pomodoro","work_minutes":1,"break_minutes":1}});self.assertTrue(self.check());self.clock.advance(60);self.assertFalse(self.check());self.clock.advance(60);self.assertTrue(self.check())
    def test_pomodoro_reset_from_work_and_rest_preserves_lock_and_accounting(self):
        b=self.make(**{'break':{'type':'pomodoro','work_minutes':1,'break_minutes':1}})
        self.engine.set_lock(b['id'],{'type':'timer','until':self.clock.value+3600})
        self.engine.runtime(b).update(sessions_used=3,reward_credit=17)
        self.store.charge(self.clock.value,b['id'],23)
        before=copy.deepcopy(b);runtime=copy.deepcopy(self.engine.runtime(b))
        self.clock.advance(30);result=self.engine.reset_pomodoro(b['id'])
        self.assertTrue(result['blocking']);self.assertEqual(result['break_status']['remaining'],60)
        self.assertEqual(b,before);self.assertEqual(self.engine.runtime(b),{**runtime,'pomodoro_started':self.clock.value})
        self.clock.advance(60);self.assertFalse(self.check())
        self.clock.advance(10);result=self.engine.reset_pomodoro(b['id'])
        self.assertTrue(result['blocking']);self.assertEqual(result['break_status']['remaining'],60)
        self.assertEqual(b,before);self.assertEqual(self.store.used(b['id'],0),23)
    def test_pomodoro_reset_persists_and_midnight_reanchors(self):
        self.clock.advance(15*3600-10)
        b=self.make(**{'break':{'type':'pomodoro','work_minutes':1,'break_minutes':1}})
        self.engine.reset_pomodoro(b['id']);self.clock.advance(5)
        other=Store(self.temp.name)
        try:
            engine=Engine(other,self.clock.wall,self.clock.monotonic,'boot-1','alice')
            self.assertEqual(engine.break_state(engine.find(b['id']))['remaining'],55)
        finally:other.db.close()
        self.clock.advance(10);self.assertEqual(self.engine.break_state(b)['remaining'],55)
    def test_pomodoro_reset_rejects_schedules_paused_and_other_breaks(self):
        for name,options in [('scheduled',{'mode':'scheduled','schedule':[{'days':[0],'start':540,'end':600}],'break':{'type':'pomodoro'}}),('paused',{'enabled':False,'break':{'type':'pomodoro'}}),('allowance',{'break':{'type':'allowance'}})]:
            b=self.make(name=name,**options);before=copy.deepcopy(self.store.state)
            self.raises(self.engine.reset_pomodoro,b['id']);self.assertEqual(self.store.state,before)
    def test_pomodoro_reset_does_not_extend_device_deadline(self):
        b=self.make(device='lock',device_minutes=5,confirm_device=True,**{'break':{'type':'pomodoro','work_minutes':1,'break_minutes':1}})
        lock=copy.deepcopy(b['lock']);until=self.engine.runtime(b)['device_until']
        self.clock.advance(70);self.engine.reset_pomodoro(b['id'])
        self.assertEqual(b['lock'],lock);self.assertEqual(self.engine.runtime(b)['device_until'],until)
        self.clock.advance(230);self.engine.tick();self.assertFalse(self.engine.active(b))
    def test_pomodoro_reset_ends_a_break_inherited_from_previous_configuration(self):
        b=self.make(**{'break':{'type':'pomodoro','work_minutes':1,'break_minutes':1}})
        self.engine.runtime(b)['break_until']=self.clock.value+300
        self.assertFalse(self.check())
        result=self.engine.reset_pomodoro(b['id'])
        self.assertTrue(result['blocking']);self.assertEqual(result['break_status']['remaining'],60)
    def consume(self,seconds,source="tab1",**kw):
        data={"url":"https://example.com","active":True,**kw};self.engine.usage(data,source)
        for _ in range(seconds//5):self.clock.advance(5);self.engine.usage(data,source)
    def test_allowance_charges(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1}});self.assertFalse(self.check());self.consume(60);self.assertTrue(self.check())
    def test_allowance_not_reset_by_clear_stats(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1}});self.consume(60);self.store.clear_statistics();self.assertTrue(self.check())
    def test_allowance_not_counted_idle(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1}});self.consume(120,idle=200);self.assertFalse(self.check())
    def test_inactive_usage_ignored(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1}});self.consume(120,active=False);self.assertFalse(self.check())
    def test_strict_usage_background(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1}});self.store.state["settings"]["strict_usage"]=True;self.consume(60,active=False);self.assertTrue(self.check())
    def test_multiple_tabs_no_double_charge(self):
        b=self.make(**{"break":{"type":"allowance","allowance_minutes":1}})
        for source in ["a","b"]:self.engine.usage({"url":"https://example.com"},source)
        for _ in range(6):
            self.clock.advance(5)
            for source in ["a","b"]:self.engine.usage({"url":"https://example.com"},source)
        self.assertEqual(self.store.used(b["id"],0),30)
    def test_rolling_refill(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1,"period":"rolling","window_minutes":1}});self.consume(60);self.assertTrue(self.check());self.clock.advance(61);self.assertFalse(self.check())
    def test_daily_refill(self):
        self.make(**{"break":{"type":"allowance","allowance_minutes":1}});self.consume(60);self.clock.advance(86400);self.assertFalse(self.check())
    def test_session_limit(self):
        self.make(**{"break":{"type":"sessions","sessions":1}});self.consume(10);self.assertFalse(self.check());self.clock.advance(121);self.assertTrue(self.check())
    def test_text_break(self):
        b=self.make(**{"break":{"type":"text","custom_text":"I choose focus","break_minutes":1}});self.assertTrue(self.check());result=self.engine.request_break(b["id"],{});self.engine.request_break(b["id"],{"answer":result["challenge"]});self.assertFalse(self.check());self.clock.advance(60);self.assertTrue(self.check())
    def test_delay_break(self):
        b=self.make(**{"break":{"type":"delay","delay_minutes":1,"break_minutes":1}});self.engine.request_break(b["id"],{});self.raises(self.engine.request_break,b["id"],{});self.clock.advance(60);self.engine.request_break(b["id"],{});self.assertFalse(self.check())
    def test_reward_requires_actual_focus(self):
        self.make(**{"break":{"type":"reward","work_minutes":1,"break_minutes":1}});self.assertTrue(self.check());self.clock.advance(3600);self.assertTrue(self.check());self.consume(60,url="https://work.org");self.assertFalse(self.check())
    def test_once_autostart(self):
        b=self.make(enabled=False,autostart={"type":"once","at":self.clock.value+60});self.engine.tick();self.assertFalse(b["enabled"]);self.clock.advance(60);self.engine.tick();self.assertTrue(b["enabled"]);self.engine.toggle(b["id"],False);self.engine.tick();self.assertFalse(b["enabled"])
    def test_signin_autostart(self):
        b=self.make(enabled=False,autostart={"type":"signin"});self.engine.tick(signin=True);self.assertTrue(b["enabled"])
    def test_daily_autostart(self):
        b=self.make(enabled=False,autostart={"type":"daily","minute":540,"days":[0]});self.engine.tick();self.assertTrue(b["enabled"]);self.engine.toggle(b["id"],False);self.engine.tick();self.assertFalse(b["enabled"])
    def test_application_bundle_and_folder(self):
        b=self.make(applications=["bundle:com.test.app","folder:/Games","binary:/tmp/game"]);self.assertTrue(self.engine.app_matches(b,{"bundle":"com.test.app","path":"/renamed.app"}));self.assertTrue(self.engine.app_matches(b,{"path":"/Games/App.app"}));self.assertFalse(self.engine.app_matches(b,{"path":"/GamesEvil/App.app"}));self.assertTrue(self.engine.app_matches(b,{"path":"/tmp/game"}))
    def test_application_binary_inside_bundle(self):
        b=self.make(applications=["binary:/Applications/Game.app/Contents/MacOS/Game"])
        self.assertTrue(self.engine.app_matches(b,{"path":"/Applications/Game.app","executable":"/Applications/Game.app/Contents/MacOS/Game"}))
    def test_device_confirmation(self):
        self.raises(self.make,device="shutdown");b=self.make(device="lock",enabled=False,confirm_device=True);self.raises(self.engine.toggle,b["id"],True)
    def test_continuous_device_block_always_has_finite_locked_duration(self):
        b=self.make(device="lock",device_minutes=1,enabled=False,confirm_device=True)
        self.engine.toggle(b["id"],True,confirm_device=True)
        self.assertTrue(self.engine.active(b));self.assertTrue(self.engine.locked(b))
        self.clock.advance(60);self.engine.tick()
        self.assertFalse(b["enabled"]);self.assertFalse(self.engine.active(b));self.assertFalse(self.engine.locked(b))
    def test_device_lock_extension_also_extends_device_duration(self):
        b=self.make(device="lock",device_minutes=1,enabled=True,confirm_device=True)
        self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+120})
        self.clock.advance(90);self.assertTrue(self.engine.active(b))
    def test_persistence(self):
        b=self.make();self.engine.set_lock(b["id"],{"type":"timer","until":self.clock.value+60});other=Store(self.temp.name);engine=Engine(other,self.clock.wall,self.clock.monotonic,"boot-1","alice");self.assertTrue(engine.locked(engine.find(b["id"])));other.db.close()
    def test_no_statistics_when_disabled(self):
        self.store.state["settings"]["statistics"]=False;self.consume(10);self.assertEqual(self.store.export_statistics(),[])
    def test_incognito_privacy(self):
        self.store.state["settings"]["incognito_statistics"]=False;self.consume(10,incognito=True);self.assertEqual(self.store.export_statistics(),[])
    def test_statistics_export_and_filters(self):
        self.consume(10);self.assertTrue(self.store.statistics(query="example")["items"]);self.assertFalse(self.store.statistics(query="unknown")["items"])
    def test_statistics_filter_multiple_blocks_without_double_count(self):
        a=self.make(**{"break":{"type":"allowance","allowance_minutes":10}})
        b=self.make(name="Other",**{"break":{"type":"allowance","allowance_minutes":10}})
        self.consume(10)
        self.assertEqual(self.store.statistics(block=a["id"])["totals"]["seconds"],10)
        self.assertEqual(self.store.statistics(block=b["id"])["totals"]["seconds"],10)
        self.assertEqual(self.store.statistics()["totals"]["seconds"],10)
    def test_password_salt(self):
        one=password_hash("abc");two=password_hash("abc");self.assertNotEqual(one,two);self.assertTrue(password_ok("abc",one));self.assertFalse(password_ok("no",one))
    def test_invalid_inputs(self):
        for kw in [{"name":""},{"websites":["a\nb"]},{"break":{"type":"unknown"}},{"break":{"type":"allowance","allowance_minutes":0}},{"color":"bad"},{"autostart":{"type":"once","at":float("nan")}},{"autostart":"bad"},{"device_minutes":float("inf")}]:
            self.raises(self.make,**kw)

if __name__=="__main__":unittest.main()
